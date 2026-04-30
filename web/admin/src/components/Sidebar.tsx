import {
  ChevronCollapseIcon,
  ChevronExpandIcon,
  DashboardIcon,
  KeyIcon,
  ServerIcon,
  ToolsIcon,
  UsersIcon,
} from './icons';

/**
 * The set of pages the sidebar can navigate between. Mirrored in
 * `AppShell`'s state so a sidebar click can switch the rendered
 * page without needing a router. Adding a new page here means
 * extending the union, the `NAV_ITEMS` array below, and the
 * page-render switch in `AppShell`.
 */
export type Page = 'overview' | 'users' | 'clients' | 'server' | 'tools';

interface NavEntry {
  page: Page;
  label: string;
  icon: (props: { size?: number; className?: string }) => React.JSX.Element;
}

const NAV_ITEMS: NavEntry[] = [
  { page: 'overview', label: 'Overview', icon: DashboardIcon },
  { page: 'users', label: 'Users', icon: UsersIcon },
  { page: 'clients', label: 'OAuth clients', icon: KeyIcon },
  { page: 'server', label: 'Server', icon: ServerIcon },
  { page: 'tools', label: 'Tools', icon: ToolsIcon },
];

/**
 * Left navigation. Always visible (sticky); collapses to icons-only
 * either via the operator's manual toggle (button at bottom) or
 * automatically via CSS media query at narrow widths (<=768px). The
 * `collapsed` prop drives the CSS class that controls width +
 * label visibility; the `<= 768px` media query takes precedence at
 * mobile widths regardless of `collapsed`.
 */
export function Sidebar({
  currentPage,
  onNavigate,
  collapsed,
  onToggleCollapsed,
}: {
  currentPage: Page;
  onNavigate: (page: Page) => void;
  collapsed: boolean;
  onToggleCollapsed: () => void;
}) {
  return (
    <aside className="sidebar" aria-label="Primary navigation">
      <div className="sidebar-brand">
        <div className="sidebar-brand-mark" aria-hidden="true">A</div>
        <span className="sidebar-brand-text">Akashic</span>
      </div>

      <nav className="sidebar-nav">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.page}
              type="button"
              className={`nav-item${currentPage === item.page ? ' active' : ''}`}
              onClick={() => onNavigate(item.page)}
              aria-current={currentPage === item.page ? 'page' : undefined}
              title={item.label}
            >
              <Icon className="nav-item-icon" />
              <span className="nav-item-label">{item.label}</span>
            </button>
          );
        })}
      </nav>

      <div className="sidebar-footer">
        <button
          type="button"
          className="sidebar-toggle"
          onClick={onToggleCollapsed}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? <ChevronExpandIcon /> : <ChevronCollapseIcon />}
        </button>
      </div>
    </aside>
  );
}
