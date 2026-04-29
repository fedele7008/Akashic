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
