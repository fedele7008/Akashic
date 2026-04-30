import { useEffect, useState } from 'react';
import { SetupStatusApi, type SetupStatus } from '../api/client';
import { WarningIcon } from './icons';

/**
 * SetupStatusBanner — Phase 8c.1.
 *
 * Banner at top of content that surfaces "what setup gates still
 * need clearing." Renders ONLY when at least one gate is
 * incomplete; clean deployments see nothing.
 *
 * Re-fetching:
 *   - On mount.
 *   - When `refreshKey` changes (parent bumps it on page nav,
 *     after registrations succeed, etc.). Cheap aggregator on
 *     the server, so re-fetching liberally is fine.
 *   - On window focus. Catches the case where the operator
 *     made a relevant change in another terminal (CLI
 *     `clients create --tenant-portal`) or another browser
 *     tab and tabbed back here.
 *
 * Failure mode: `SetupStatusApi.get()` returns null on any error
 * (network, 5xx, malformed body). The banner then renders
 * nothing — a status check that itself errors should never be
 * more disruptive than what it's trying to surface.
 */
export function SetupStatusBanner({ refreshKey = 0 }: { refreshKey?: number }) {
  const [status, setStatus] = useState<SetupStatus | null>(null);
  const [loaded, setLoaded] = useState(false);
  // Local tick used in addition to refreshKey, so the focus
  // listener can trigger a refetch without colliding with the
  // parent-driven refreshKey.
  const [focusTick, setFocusTick] = useState(0);

  useEffect(() => {
    let cancelled = false;
    SetupStatusApi.get().then((s) => {
      if (cancelled) return;
      setStatus(s);
      setLoaded(true);
    });
    return () => {
      cancelled = true;
    };
  }, [refreshKey, focusTick]);

  useEffect(() => {
    const bump = () => setFocusTick((t) => t + 1);
    // Window focus catches CLI-driven changes from another
    // terminal; the custom event catches in-tab changes (e.g.,
    // ClientsCreate just registered a portal-flagged client).
    window.addEventListener('focus', bump);
    window.addEventListener('akashic:setup-changed', bump);
    return () => {
      window.removeEventListener('focus', bump);
      window.removeEventListener('akashic:setup-changed', bump);
    };
  }, []);

  if (!loaded || !status) return null;

  const items = buildItems(status);
  if (items.length === 0) return null;

  return (
    <div className="setup-banner" role="status">
      <div className="setup-banner-icon" aria-hidden="true">
        <WarningIcon size={20} />
      </div>
      <div className="setup-banner-body">
        <div className="setup-banner-title">Setup incomplete</div>
        <ul className="setup-banner-items">
          {items.map((item) => (
            <li key={item.key}>
              <strong>{item.title}.</strong> {item.detail}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

/**
 * Each gate, in the order an operator would naturally clear them.
 * Bootstrap is foundational — without it nothing else makes sense
 * — so we surface only that one when it's the failing gate, even
 * if other gates are also `false`. Otherwise downstream noise
 * ("LDAP not OK") swamps the actionable signal ("you haven't run
 * bootstrap yet, that's why").
 */
interface BannerItem {
  key: string;
  title: string;
  detail: string;
}

function buildItems(s: SetupStatus): BannerItem[] {
  if (!s.bootstrap_complete) {
    return [
      {
        key: 'bootstrap',
        title: 'Bootstrap not yet run',
        detail:
          'Run `akashic-cli bootstrap create-root` to create the deployment\'s first root user. Other admin actions are blocked until this completes.',
      },
    ];
  }

  const out: BannerItem[] = [];

  if (!s.ldap_ok) {
    out.push({
      key: 'ldap',
      title: 'LDAP unreachable',
      detail:
        'The LDAP directory isn\'t responding. Sign-in and signup will fail until it recovers — check the `ldap` container and the akashic server logs.',
    });
  }

  if (!s.tenant_portal_registered) {
    out.push({
      key: 'tenant-portal',
      title: 'No first-party clients registered yet',
      detail:
        'Register the OAuth clients you (the operator) own — your tenant portal, mail/calendar/drive apps, and so on — and tick "Mark as first-party" on each. The flag is what distinguishes them from third-party developer integrations and (in Chapter 7) from clients that need consent prompts. You can use `akashic-cli clients create --type WEB --tenant-portal …` or the OAuth Clients page below.',
    });
  }

  return out;
}
