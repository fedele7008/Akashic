import { useEffect, useRef, useState } from 'react';
import { SessionApi, type SessionInfo } from '../api/client';
import { ChevronDownIcon, LogoutIcon } from './icons';

/**
 * Topbar — page title on the left, avatar + dropdown menu on the
 * right. Page title is parent-supplied (parent owns "what page is
 * showing" anyway, so passing the title down is one less coupling
 * than reading from a routing context).
 *
 * Avatar dropdown holds:
 *   - Header: full username + role
 *   - Logout button (RP-Initiated Logout via SessionApi.logout())
 *
 * The dropdown closes on outside-click via a document-level
 * mousedown listener installed only while it's open. Escape closes
 * too — both are minimum-viable affordances expected of a SaaS
 * dashboard avatar menu.
 */
export function Topbar({
  pageTitle,
  session,
}: {
  pageTitle: string;
  session: SessionInfo;
}) {
  const [menuOpen, setMenuOpen] = useState(false);
  const [loggingOut, setLoggingOut] = useState(false);
  const wrapRef = useRef<HTMLDivElement>(null);

  // Outside-click + Escape to close. Listener only installed while
  // the menu is open so it doesn't run on every render.
  useEffect(() => {
    if (!menuOpen) return;
    const onDown = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) {
        setMenuOpen(false);
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMenuOpen(false);
    };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [menuOpen]);

  const handleLogout = async () => {
    setLoggingOut(true);
    let authLogoutUrl = '';
    try {
      authLogoutUrl = await SessionApi.logout();
    } catch {
      // Even on logout error, navigate — the user wants OUT. Falling
      // back to '/' means the BFF session may already be cleared but
      // the auth-server session might survive; a future fresh login
      // would be silent. Acceptable degraded behavior compared to
      // "the button did nothing."
    }
    window.location.href = authLogoutUrl || '/';
  };

  // Two-letter monogram from the username. Falls back to "·" when
  // the session doesn't carry a username (rare; user_id-only).
  const initials = (session.username || session.user_id)
    .slice(0, 2)
    .toUpperCase() || '·';

  return (
    <header className="topbar" role="banner">
      <h1 className="topbar-title">{pageTitle}</h1>
      <div className="topbar-actions" ref={wrapRef}>
        <button
          type="button"
          className={`avatar${menuOpen ? ' open' : ''}`}
          onClick={() => setMenuOpen((o) => !o)}
          aria-haspopup="menu"
          aria-expanded={menuOpen}
          aria-label="Account menu"
          style={{ marginTop: 0 }}
        >
          {initials}
        </button>
        {/* The chevron is decorative — clicking it opens the same
            menu the avatar opens, but it makes the affordance more
            obvious to operators who don't expect avatar circles to
            be interactive. */}
        <button
          type="button"
          onClick={() => setMenuOpen((o) => !o)}
          className="secondary"
          aria-hidden="true"
          tabIndex={-1}
          style={{
            marginTop: 0,
            padding: '6px',
            background: 'transparent',
            border: 'none',
            color: 'var(--text-muted)',
          }}
        >
          <ChevronDownIcon size={16} />
        </button>

        {menuOpen && (
          <div className="avatar-menu" role="menu">
            <div className="avatar-menu-header">
              <strong>{session.username || session.user_id}</strong>
              <span>{session.user_type} · {session.email || 'no email'}</span>
            </div>
            <button
              type="button"
              role="menuitem"
              onClick={() => void handleLogout()}
              disabled={loggingOut}
            >
              <LogoutIcon size={16} />
              {loggingOut ? 'Signing out…' : 'Sign out'}
            </button>
          </div>
        )}
      </div>
    </header>
  );
}
