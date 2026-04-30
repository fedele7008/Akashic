import { useEffect, useState } from 'react';
import { AdminToolsApi, type AdminTool } from '../api/client';
import {
  CubeIcon,
  DatabaseIcon,
  DirectoryIcon,
  ExternalLinkIcon,
  GrafanaIcon,
  VaultIcon,
} from './icons';

/**
 * ToolsPage — Phase 8c.5.
 *
 * Card grid linking out to operator-side debugging tools (Grafana,
 * Adminer, RedisInsight, Vault UI, phpLDAPadmin). Cards render only
 * for tools with a configured URL on the BFF, so production
 * deployments that don't ship every tool see a clean, accurate page
 * rather than a wall of broken links.
 *
 * Each card opens in a new tab — these are external services, not
 * part of the admin SPA, and the operator usually wants to keep the
 * admin UI available alongside while debugging.
 *
 * Why not health-ping each link to colour the card: deferred. The
 * tools tab on each card would have to make a CORS request from
 * the admin origin to whatever each tool's origin is, which usually
 * fails (none of these tools serve `Access-Control-Allow-Origin`).
 * Worth doing later via a BFF-side ping that the FE polls, but the
 * value is marginal — operators already see "tool down" the moment
 * they click the link.
 */
export function ToolsPage() {
  const [tools, setTools] = useState<AdminTool[] | null>(null);

  useEffect(() => {
    AdminToolsApi.list().then(setTools);
  }, []);

  return (
    <>
      <div className="page-header">
        <div>
          <h2 className="page-header-title">Tools</h2>
          <p className="page-header-sub">
            External debugging tools — Grafana for logs/metrics,
            Adminer for Postgres, RedisInsight for Redis, Vault for
            secrets/PKI, phpLDAPadmin for the directory. Only tools
            with a configured URL on the admin-bff appear here.
          </p>
        </div>
      </div>

      {tools === null && (
        <p className="hint" style={{ marginTop: '1rem' }}>Loading tools…</p>
      )}

      {tools !== null && tools.length === 0 && (
        <p className="hint" style={{ marginTop: '1rem' }}>
          No tools configured. Set <code>AKASHIC_BFF_TOOLS_*_URL</code> env
          vars on the admin-bff to surface them here. See <code>.env.example</code>{' '}
          for the supported keys and typical dev URLs.
        </p>
      )}

      {tools !== null && tools.length > 0 && (
        <div className="grid">
          {tools.map((t) => (
            <ToolCard key={t.key} tool={t} />
          ))}
        </div>
      )}
    </>
  );
}

/**
 * One card in the tools grid. Wrapped in an <a> with target="_blank"
 * + rel="noopener" — the tools live on different origins and we want
 * the admin UI to stay open. `noreferrer` is omitted intentionally:
 * since the operator is logged in to both, leaking the Referer to
 * an internal tool isn't a concern.
 */
function ToolCard({ tool }: { tool: AdminTool }) {
  return (
    <a
      className="panel interactive tool-card"
      href={tool.url}
      target="_blank"
      rel="noopener"
    >
      <div className="tool-card-head">
        <div className="tool-card-icon" aria-hidden="true">
          {iconFor(tool.key)}
        </div>
        <h3 style={{ margin: 0 }}>{tool.label}</h3>
        <ExternalLinkIcon
          className="tool-card-external"
          style={{ color: 'var(--text-subtle)' }}
        />
      </div>
      <p className="panel-sub" style={{ wordBreak: 'break-all' }}>
        {tool.url}
      </p>
    </a>
  );
}

function iconFor(key: AdminTool['key']) {
  switch (key) {
    case 'grafana':
      return <GrafanaIcon size={22} />;
    case 'adminer':
      return <DatabaseIcon size={22} />;
    case 'redisinsight':
      return <CubeIcon size={22} />;
    case 'vault':
      return <VaultIcon size={22} />;
    case 'phpldapadmin':
      return <DirectoryIcon size={22} />;
  }
}
