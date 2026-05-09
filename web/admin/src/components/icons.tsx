/**
 * Inline SVG icon components.
 *
 * Hand-rolled rather than pulling in lucide-react / heroicons —
 * three icons are too small a footprint to justify a new dependency.
 * Each icon takes a `size` (default 18) and an optional className;
 * `currentColor` inherits whatever color the parent sets so the
 * sidebar's active-vs-muted state and the topbar's avatar-button
 * styling work without per-icon overrides.
 */

import type { CSSProperties } from 'react';

interface IconProps {
  size?: number;
  className?: string;
  style?: CSSProperties;
}

const base = (size: number) => ({
  width: size,
  height: size,
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 2,
  strokeLinecap: 'round' as const,
  strokeLinejoin: 'round' as const,
});

/** Dashboard / overview — 2x2 grid of squares. */
export function DashboardIcon({ size = 18, className, style }: IconProps) {
  return (
    <svg {...base(size)} className={className} style={style} aria-hidden="true">
      <rect x="3" y="3" width="7" height="7" rx="1" />
      <rect x="14" y="3" width="7" height="7" rx="1" />
      <rect x="3" y="14" width="7" height="7" rx="1" />
      <rect x="14" y="14" width="7" height="7" rx="1" />
    </svg>
  );
}

/** OAuth clients — key icon. */
export function KeyIcon({ size = 18, className, style }: IconProps) {
  return (
    <svg {...base(size)} className={className} style={style} aria-hidden="true">
      <circle cx="7.5" cy="15.5" r="4.5" />
      <path d="M11 12L21 2" />
      <path d="M16 7L19 10" />
      <path d="M14 9L18 13" />
    </svg>
  );
}

/** Sidebar collapse / expand — chevron-double pointing left/right. */
export function ChevronCollapseIcon({ size = 18, className, style }: IconProps) {
  return (
    <svg {...base(size)} className={className} style={style} aria-hidden="true">
      <path d="M11 17l-5-5 5-5" />
      <path d="M18 17l-5-5 5-5" />
    </svg>
  );
}
export function ChevronExpandIcon({ size = 18, className, style }: IconProps) {
  return (
    <svg {...base(size)} className={className} style={style} aria-hidden="true">
      <path d="M13 17l5-5-5-5" />
      <path d="M6 17l5-5-5-5" />
    </svg>
  );
}

/** Avatar dropdown — chevron-down. */
export function ChevronDownIcon({ size = 18, className, style }: IconProps) {
  return (
    <svg {...base(size)} className={className} style={style} aria-hidden="true">
      <path d="M6 9l6 6 6-6" />
    </svg>
  );
}

/** Logout — door with arrow exiting. */
export function LogoutIcon({ size = 18, className, style }: IconProps) {
  return (
    <svg {...base(size)} className={className} style={style} aria-hidden="true">
      <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
      <path d="M16 17l5-5-5-5" />
      <path d="M21 12H9" />
    </svg>
  );
}

/** Warning — triangle with exclamation; setup-status banner. */
export function WarningIcon({ size = 18, className, style }: IconProps) {
  return (
    <svg {...base(size)} className={className} style={style} aria-hidden="true">
      <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  );
}

/** Shield — sidebar entry for the policy page. */
export function ShieldIcon({ size = 18, className, style }: IconProps) {
  return (
    <svg {...base(size)} className={className} style={style} aria-hidden="true">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}

/** Users — sidebar entry for user management. Person + small "+" hint. */
export function UsersIcon({ size = 18, className, style }: IconProps) {
  return (
    <svg {...base(size)} className={className} style={style} aria-hidden="true">
      <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
      <circle cx="9" cy="7" r="4" />
      <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
      <path d="M16 3.13a4 4 0 0 1 0 7.75" />
    </svg>
  );
}

/** Server stack — sidebar entry for the Server control page. */
export function ServerIcon({ size = 18, className, style }: IconProps) {
  return (
    <svg {...base(size)} className={className} style={style} aria-hidden="true">
      <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
      <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
      <line x1="6" y1="6" x2="6.01" y2="6" />
      <line x1="6" y1="18" x2="6.01" y2="18" />
    </svg>
  );
}

/** Wrench / tools — sidebar entry for the Tools page. */
export function ToolsIcon({ size = 18, className, style }: IconProps) {
  return (
    <svg {...base(size)} className={className} style={style} aria-hidden="true">
      <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
    </svg>
  );
}

/* ─── Per-tool icons (Phase 8c.5) ───
   Hand-rolled glyphs — none of these match the vendor's official
   logo (we'd need licensed assets for that), but each is
   distinctive enough at a glance that the operator scans the grid
   without re-reading every label. */

/** Grafana — abstract chart bars. */
export function GrafanaIcon({ size = 18, className, style }: IconProps) {
  return (
    <svg {...base(size)} className={className} style={style} aria-hidden="true">
      <path d="M3 20h18" />
      <rect x="5" y="11" width="3" height="9" />
      <rect x="10.5" y="6" width="3" height="14" />
      <rect x="16" y="14" width="3" height="6" />
    </svg>
  );
}

/** Adminer — database cylinder. */
export function DatabaseIcon({ size = 18, className, style }: IconProps) {
  return (
    <svg {...base(size)} className={className} style={style} aria-hidden="true">
      <ellipse cx="12" cy="5" rx="9" ry="3" />
      <path d="M3 5v6c0 1.66 4 3 9 3s9-1.34 9-3V5" />
      <path d="M3 11v6c0 1.66 4 3 9 3s9-1.34 9-3v-6" />
    </svg>
  );
}

/** RedisInsight — cube (memory store). */
export function CubeIcon({ size = 18, className, style }: IconProps) {
  return (
    <svg {...base(size)} className={className} style={style} aria-hidden="true">
      <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
      <polyline points="3.27 6.96 12 12.01 20.73 6.96" />
      <line x1="12" y1="22.08" x2="12" y2="12" />
    </svg>
  );
}

/** Vault — closed lock for secrets/PKI. */
export function VaultIcon({ size = 18, className, style }: IconProps) {
  return (
    <svg {...base(size)} className={className} style={style} aria-hidden="true">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </svg>
  );
}

/** phpLDAPadmin — directory tree. */
export function DirectoryIcon({ size = 18, className, style }: IconProps) {
  return (
    <svg {...base(size)} className={className} style={style} aria-hidden="true">
      <circle cx="12" cy="5" r="2" />
      <circle cx="6" cy="19" r="2" />
      <circle cx="18" cy="19" r="2" />
      <path d="M12 7v5" />
      <path d="M12 12h-6v5" />
      <path d="M12 12h6v5" />
    </svg>
  );
}

/** External-link — small "opens in new tab" indicator on tool cards. */
export function ExternalLinkIcon({ size = 14, className, style }: IconProps) {
  return (
    <svg {...base(size)} className={className} style={style} aria-hidden="true">
      <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
      <polyline points="15 3 21 3 21 9" />
      <line x1="10" y1="14" x2="21" y2="3" />
    </svg>
  );
}
