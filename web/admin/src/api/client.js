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
