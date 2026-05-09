import { useState } from 'react';
import type { SessionInfo } from '../api/client';
import { ClientsPage } from './ClientsPage';
import { OverviewPage } from './OverviewPage';
import { PolicyPage } from './PolicyPage';
import { ServerPage } from './ServerPage';
import { SetupStatusBanner } from './SetupStatusBanner';
import { Sidebar, type Page } from './Sidebar';
import { ToolsPage } from './ToolsPage';
import { Topbar } from './Topbar';
import { UsersPage } from './UsersPage';

/**
 * Dashboard — the post-bootstrap, post-login app shell.
 *
 * Layout (CSS-grid driven; see styles.css `.app-shell`):
 *
 *   ┌──────────┬───────────────────────────────────────────────┐
 *   │          │  Topbar (page title · avatar dropdown)        │
 *   │ Sidebar  ├───────────────────────────────────────────────┤
 *   │  • icon  │                                               │
 *   │    label │              Page content                     │
 *   │  • ...   │                                               │
 *   │ ─────    │                                               │
 *   │  toggle  │                                               │
 *   └──────────┴───────────────────────────────────────────────┘
 *
 * State here is intentionally minimal: which page is showing,
 * whether the operator manually collapsed the sidebar. Each page
 * owns its own data state. Adding a page = extend the `Page`
 * union (in Sidebar.tsx) + add a NAV_ITEMS entry + a case to the
 * render switch below.
 *
 * Why not react-router: the admin web has 2 pages today, possibly
 * 4 by year-end (users, audit). A discriminated union state field
 * is a tighter fit than pulling in `react-router-dom` for this
 * size; cost is no URL persistence on refresh, which an operator
 * console can live without.
 */
export function Dashboard({ session }: { session: SessionInfo }) {
  const [page, setPage] = useState<Page>('overview');
  const [collapsed, setCollapsed] = useState(false);
  // Monotonic counter the SetupStatusBanner uses as a refetch
  // trigger. Bumped on page navigation (a likely moment for
  // setup-state to have changed — e.g., user just registered
  // a tenant-portal client on the Clients page and is now
  // returning to Overview).
  const [bannerRefreshKey, setBannerRefreshKey] = useState(0);

  const handleNavigate = (next: Page) => {
    setPage(next);
    setBannerRefreshKey((k) => k + 1);
  };

  const pageTitle = pageTitleFor(page);

  return (
    <div className={`app-shell${collapsed ? ' collapsed' : ''}`}>
      <Sidebar
        currentPage={page}
        onNavigate={handleNavigate}
        collapsed={collapsed}
        onToggleCollapsed={() => setCollapsed((c) => !c)}
      />
      <Topbar pageTitle={pageTitle} session={session} />
      <main className="content">
        <div className="content-inner">
          <SetupStatusBanner refreshKey={bannerRefreshKey} />
          {page === 'overview' && (
            <OverviewPage session={session} onNavigate={handleNavigate} />
          )}
          {page === 'users' && <UsersPage session={session} />}
          {page === 'clients' && <ClientsPage session={session} />}
          {page === 'policy' && <PolicyPage />}
          {page === 'server' && <ServerPage />}
          {page === 'tools' && <ToolsPage />}
        </div>
      </main>
    </div>
  );
}

function pageTitleFor(page: Page): string {
  switch (page) {
    case 'overview':
      return 'Overview';
    case 'users':
      return 'Users';
    case 'clients':
      return 'OAuth clients';
    case 'policy':
      return 'Policy';
    case 'server':
      return 'Server';
    case 'tools':
      return 'Tools';
  }
}
