"use client";

/**
 * Tiny client-side wrapper around <akashic-signup>. The wrapper does
 * one thing the headless widget can't do for us: bridge the
 * `akashic-signup-success` custom event to a navigation. Pure React
 * server components can't attach event listeners, so this needs to
 * be "use client".
 *
 * Tenants integrating Akashic widgets into their own products write
 * the same ~10 lines themselves (or skip the auto-redirect if their
 * UX wants something else, like a confirmation dialog).
 */

import { useEffect, useRef } from "react";

interface Props {
  /** Where to send the user after they create an account. Default: /sign-in. */
  onSuccessRedirect?: string;
}

export function SignUpWidget({ onSuccessRedirect = "/sign-in" }: Props) {
  const hostRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    const handler = () => {
      window.location.href = onSuccessRedirect;
    };
    host.addEventListener("akashic-signup-success", handler);
    return () => host.removeEventListener("akashic-signup-success", handler);
  }, [onSuccessRedirect]);

  return (
    <div ref={hostRef}>
      <akashic-signup />
    </div>
  );
}
