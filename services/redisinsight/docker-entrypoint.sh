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

    // Step 2: Check existing databases — update if TLS changed, remove stale entries
    const wantTls = '${REDIS_TLS}' === 'on';
    const dbs = await api('GET', '/api/databases');
    let found = null;
    for (const db of dbs.body) {
        if (db.name === 'Akashic Redis') {
            found = db;
        } else {
            console.log('[redisinsight-init] Removing stale database: ' + db.name + ' (' + db.id + ')');
            await api('DELETE', '/api/databases/' + db.id);
        }
    }
    if (found) {
        if (found.tls === wantTls) {
            console.log('[redisinsight-init] Database \"Akashic Redis\" already configured (TLS=' + (wantTls ? 'on' : 'off') + ').');
            return;
        }
        // TLS config changed — update in place (keeps the same ID so browser doesn't break)
        console.log('[redisinsight-init] TLS config changed (was ' + (found.tls ? 'on' : 'off') + ', now ' + (wantTls ? 'on' : 'off') + '). Updating...');
        const update = { tls: wantTls };
        if (wantTls && fs.existsSync('${CA_CERT_PATH}')) {
            update.verifyServerCert = true;
            update.caCert = {
                name: 'Akashic Internal CA',
                certificate: fs.readFileSync('${CA_CERT_PATH}', 'utf8')
            };
        } else {
            update.verifyServerCert = false;
            update.caCert = null;
        }
        const patchResult = await api('PATCH', '/api/databases/' + found.id, update);
        if (patchResult.status === 200) {
            console.log('[redisinsight-init] Database updated (TLS=' + (wantTls ? 'on' : 'off') + ').');
        } else {
            console.log('[redisinsight-init] Failed to update database:', JSON.stringify(patchResult.body));
        }
        return;
    }

    // Step 3: Build database config
    const dbConfig = {
        name: 'Akashic Redis',
        host: '${REDIS_HOST}',
        port: ${REDIS_PORT},
    };
    if ('${REDIS_PASSWORD}') dbConfig.password = '${REDIS_PASSWORD}';

    if ('${REDIS_TLS}' === 'on' && fs.existsSync('${CA_CERT_PATH}')) {
        dbConfig.tls = true;
        dbConfig.verifyServerCert = true;
        dbConfig.caCert = {
            name: 'Akashic Internal CA',
            certificate: fs.readFileSync('${CA_CERT_PATH}', 'utf8')
        };
        console.log('[redisinsight-init] TLS enabled with CA cert verification.');
    } else {
        dbConfig.tls = false;
        console.log('[redisinsight-init] TLS disabled.');
    }

    // Step 4: Add database
    console.log('[redisinsight-init] Adding Redis database...');
    const result = await api('POST', '/api/databases', dbConfig);
    if (result.status === 201) {
        console.log('[redisinsight-init] Database \"Akashic Redis\" added successfully.');
    } else {
        console.log('[redisinsight-init] Failed to add database:', JSON.stringify(result.body));
    }
})().catch(err => console.error('[redisinsight-init] Error:', err.message));
"

# Wait for RedisInsight process
wait $RI_PID
