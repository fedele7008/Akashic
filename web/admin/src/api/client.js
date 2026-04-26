// Thin fetch wrappers + CSRF helper for the admin FE.
//
// The BFF sets a CSRF cookie on first response (see
// pkg/admin_bff/csrf.go); for any state-changing request we have to
// echo that cookie's value back in the X-Akashic-CSRF header.
const CSRF_COOKIE = 'akashic_csrf';
const CSRF_HEADER = 'X-Akashic-CSRF';
/** Read a cookie value by name. Returns '' if not set. */
function readCookie(name) {
    const target = name + '=';
    for (const part of document.cookie.split(';')) {
        const trimmed = part.trim();
        if (trimmed.startsWith(target)) {
            return decodeURIComponent(trimmed.substring(target.length));
        }
    }
    return '';
}
export class SessionApi {
    /**
     * GET /api/session — returns the logged-in user's info.
     *
     * On 401 (no session OR expired) returns null rather than throwing,
     * because "not logged in" is a normal expected state at this
     * endpoint. The App shell switches its rendered view based on the
     * null/non-null outcome.
     *
     * Other failure modes (network down, BFF crashed) DO throw, since
     * those represent infrastructure problems the user should see.
     */
    static async info() {
        const r = await fetch('/api/session', {
            method: 'GET',
            credentials: 'same-origin',
        });
        if (r.status === 401) {
            return null; // not logged in -- normal
        }
        const body = await r.json();
        if (!r.ok || !body.success) {
            throw new Error(body.error?.message ?? `Session check failed (HTTP ${r.status})`);
        }
        return body.data;
    }
    /**
     * POST /logout — invalidates the BFF session and returns the auth
     * server's RP-Initiated Logout URL.
     *
     * The full logout chain is:
     *
     *   1. POST /logout (BFF)        → kills the BFF session + cookie
     *   2. GET <auth_logout_url>     → kills the auth-server session,
     *                                  redirects browser back to admin
     *
     * Without the second hop, the auth-server's session cookie survives,
     * and the next "Sign in" click silently re-uses it (single-sign-on
     * is great until you explicitly want OUT). The caller navigates the
     * browser to the returned URL to complete the chain.
     *
     * Returns the URL the FE should navigate to next; empty string means
     * the BFF couldn't compute one (rare; happens only if OAuth init
     * failed at BFF startup).
     */
    static async logout() {
        const csrf = readCookie(CSRF_COOKIE);
        const r = await fetch('/logout', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                [CSRF_HEADER]: csrf,
            },
        });
        try {
            const body = await r.json();
            return body.data?.auth_logout_url ?? '';
        }
        catch {
            return '';
        }
    }
}
export class BootstrapApi {
    /**
     * GET /api/bootstrap/status — fetch the current bootstrap state.
     * Always reachable, both in bootstrap-required and normal modes.
     */
    static async status() {
        const r = await fetch('/api/bootstrap/status', {
            method: 'GET',
            credentials: 'same-origin',
        });
        const body = await r.json();
        if (!r.ok || !body.success) {
            throw new Error(body.error?.message ?? `Status check failed (HTTP ${r.status})`);
        }
        return body.data;
    }
    /**
     * POST /api/bootstrap/create-root — submit the bootstrap form.
     * On any structured error we throw with the server-supplied message
     * so the caller can render it directly to the user.
     */
    static async createRoot(req) {
        const csrf = readCookie(CSRF_COOKIE);
        if (!csrf) {
            // The BFF sets the CSRF cookie on the very first response. If
            // we don't have it yet, do a no-op GET to acquire one. In
            // practice the App component's status call already did this,
            // but defensive double-check.
            await fetch('/api/health', { credentials: 'same-origin' });
        }
        const r = await fetch('/api/bootstrap/create-root', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                [CSRF_HEADER]: readCookie(CSRF_COOKIE),
            },
            body: JSON.stringify(req),
        });
        const body = await r.json();
        if (!r.ok || !body.success) {
            const err = new Error(body.error?.message ?? `Submission failed (HTTP ${r.status})`);
            // Attach the structured error so the caller can branch on .code
            // for special handling (e.g., RATE_LIMITED).
            err.apiError = body.error;
            throw err;
        }
        return body.data;
    }
}
