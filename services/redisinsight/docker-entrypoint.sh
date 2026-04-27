#!/bin/sh
set -e

REDIS_HOST="${RI_REDIS_HOST:-redis}"
REDIS_PORT="${RI_REDIS_PORT:-6379}"
REDIS_PASSWORD="${RI_REDIS_PASSWORD:-}"
REDIS_TLS="${RI_REDIS_TLS:-off}"
CA_CERT_PATH="/certs/redis/ca.crt"

# Start RedisInsight in background
./docker-entry.sh node redisinsight/api/dist/src/main &
RI_PID=$!

# Wait for API to be ready
echo "[redisinsight-init] Waiting for RedisInsight API..."
until wget -qO- http://127.0.0.1:5540/api/info >/dev/null 2>&1; do sleep 1; done
echo "[redisinsight-init] API is ready."

# Auto-provision using node (reliable JSON handling, available in the image)
node -e "
const http = require('http');
const fs = require('fs');

function api(method, path, body) {
    return new Promise((resolve, reject) => {
        const data = body ? JSON.stringify(body) : null;
        const opts = {
            hostname: '127.0.0.1', port: 5540, path, method,
            headers: { 'Content-Type': 'application/json' }
        };
        if (data) opts.headers['Content-Length'] = Buffer.byteLength(data);
        const req = http.request(opts, res => {
            let body = '';
            res.on('data', c => body += c);
            res.on('end', () => resolve({ status: res.statusCode, body: body ? JSON.parse(body) : null }));
        });
        req.on('error', reject);
        if (data) req.write(data);
        req.end();
    });
}

(async () => {
    // Step 1: Accept agreements (required before any encrypted operation)
    const settings = await api('GET', '/api/settings');
    if (!settings.body.agreements || !settings.body.agreements.eula) {
        console.log('[redisinsight-init] Accepting agreements...');
        await api('PATCH', '/api/settings', {
            agreements: { eula: true, encryption: true, analytics: false, notifications: false }
        });
        console.log('[redisinsight-init] Agreements accepted.');
    }

    // Akashic uses TWO logical Redis databases on the same instance:
    //   DB 0 — owned by the akashic-server (auth-server sessions,
    //          authorization codes, rate-limit counters)
    //   DB 1 — owned by the admin-bff (browser-session store)
    //
    // Each gets its OWN RedisInsight connection card, so an operator
    // browsing redisinsight.<domain> immediately sees both keyspaces
    // without having to know about the database-index selector inside
    // a single connection. Two services, two stores, two cards.
    const desiredDbs = [
        {
            name: 'Akashic Redis (akashic server)',
            db:   0,
            note: 'auth-server sessions, OAuth codes, rate-limit counters',
        },
        {
            name: 'Akashic Redis (admin-bff)',
            db:   1,
            note: 'admin-bff browser sessions',
        },
    ];

    // RedisInsight does NOT expose POST /api/certificates/ca — CA
    // certs only get created as a side-effect of inlining them in a
    // database POST under `caCert: { name, certificate }`. And it
    // rejects duplicate CA-cert names with HTTP 400. So if two
    // database connections both inline the same name, the second
    // collides.
    //
    // Workaround: give each database its OWN uniquely-named copy of
    // the CA. Two cert resources for the same underlying PEM is a
    // minor waste, but it sidesteps the collision rule entirely and
    // doesn't depend on any phantom API. Cleanup of stale cert
    // resources is handled below before we add new connections.

    function buildDbConfig(spec, wantTls) {
        const cfg = {
            name: spec.name,
            host: '${REDIS_HOST}',
            port: ${REDIS_PORT},
            db:   spec.db,
        };
        if ('${REDIS_PASSWORD}') cfg.password = '${REDIS_PASSWORD}';
        if (wantTls && fs.existsSync('${CA_CERT_PATH}')) {
            cfg.tls = true;
            cfg.verifyServerCert = true;
            cfg.caCert = {
                // Per-connection cert name, includes db index to keep
                // it unique across connections.
                name: 'Akashic Internal CA (db ' + spec.db + ')',
                certificate: fs.readFileSync('${CA_CERT_PATH}', 'utf8'),
            };
        } else {
            cfg.tls = false;
        }
        return cfg;
    }

    // Clean up stale CA cert resources from any previous run. Without
    // this, a re-run that's already past the database-add step would
    // find leftover certs named 'Akashic Internal CA (db 0)' etc.
    // and re-collide on the same name. We delete every cert whose
    // name starts with 'Akashic Internal CA' before adding new ones.
    async function cleanStaleCACerts() {
        const list = await api('GET', '/api/certificates/ca');
        for (const c of list.body || []) {
            if (typeof c.name === 'string' && c.name.startsWith('Akashic Internal CA')) {
                console.log('[redisinsight-init] Removing stale CA cert: ' + c.name);
                await api('DELETE', '/api/certificates/ca/' + c.id);
            }
        }
    }

    // Step 2: reconcile the existing RedisInsight database list
    // against the desired list. Three actions per existing entry:
    //   - matches a desired entry by name, with same TLS setting → keep
    //   - matches by name but TLS setting changed → patch in place
    //   - doesn't match any desired name → DELETE (stale leftover from
    //     a previous schema, e.g. the old 'Akashic Redis' card)
    const wantTls = '${REDIS_TLS}' === 'on';
    const desiredNames = new Set(desiredDbs.map(d => d.name));
    const existing = await api('GET', '/api/databases');
    const byName = {};
    for (const db of existing.body) {
        if (desiredNames.has(db.name)) {
            byName[db.name] = db;
        } else {
            console.log('[redisinsight-init] Removing stale database: ' + db.name + ' (' + db.id + ')');
            await api('DELETE', '/api/databases/' + db.id);
        }
    }

    // Clean stale CA cert resources before we add new databases so
    // their inlined certs don't collide with names from a prior run.
    await cleanStaleCACerts();

    // Step 3: create / update each desired connection
    for (const spec of desiredDbs) {
        const found = byName[spec.name];
        if (found) {
            if (found.tls === wantTls && found.db === spec.db) {
                console.log('[redisinsight-init] \"' + spec.name + '\" already configured (TLS=' + (wantTls ? 'on' : 'off') + ', db=' + spec.db + ').');
                continue;
            }
            console.log('[redisinsight-init] \"' + spec.name + '\" config changed; updating...');
            const update = { tls: wantTls, db: spec.db };
            if (wantTls && fs.existsSync('${CA_CERT_PATH}')) {
                update.verifyServerCert = true;
                update.caCert = {
                    name: 'Akashic Internal CA (db ' + spec.db + ')',
                    certificate: fs.readFileSync('${CA_CERT_PATH}', 'utf8'),
                };
            } else {
                update.verifyServerCert = false;
                update.caCert = null;
            }
            const r = await api('PATCH', '/api/databases/' + found.id, update);
            if (r.status === 200) {
                console.log('[redisinsight-init] \"' + spec.name + '\" updated.');
            } else {
                console.log('[redisinsight-init] Failed to update \"' + spec.name + '\":', JSON.stringify(r.body));
            }
        } else {
            console.log('[redisinsight-init] Adding \"' + spec.name + '\" (' + spec.note + ')...');
            const r = await api('POST', '/api/databases', buildDbConfig(spec, wantTls));
            if (r.status === 201) {
                console.log('[redisinsight-init] \"' + spec.name + '\" added (TLS=' + (wantTls ? 'on' : 'off') + ', db=' + spec.db + ').');
            } else {
                console.log('[redisinsight-init] Failed to add \"' + spec.name + '\":', JSON.stringify(r.body));
            }
        }
    }
})().catch(err => console.error('[redisinsight-init] Error:', err.message));
"

# Wait for RedisInsight process
wait $RI_PID
