import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useEffect, useState } from 'react';
import { BootstrapApi, SessionApi, } from './api/client';
import { BootstrapForm } from './components/BootstrapForm';
import { BootstrapAlreadyComplete } from './components/BootstrapAlreadyComplete';
import { Dashboard } from './components/Dashboard';
/**
 * App is the three-state shell:
 *
 *   loading                                    → spinner
 *   bootstrap not complete                     → BootstrapForm
 *   bootstrap complete + logged in             → Dashboard
 *   bootstrap complete + NOT logged in         → "Sign in" landing
 *                                                with redirect button
 *
 * The "redirect to /login" leg deliberately uses a button rather than
 * an automatic redirect on load. Reasons:
 *  - lets the user see what's happening before bouncing them out
 *  - avoids a redirect loop if /login is broken
 *  - matches the affordance pattern of any well-behaved consumer
 *    site (no surprise navigation)
 *
 * Phase 8+ will likely add a router so /admin/users, /admin/clients
 * etc. are real routes. For now everything lives inside this single
 * shell.
 */
export function App() {
    const [status, setStatus] = useState(null);
    const [session, setSession] = useState(null);
    const [loading, setLoading] = useState(true);
    const [statusError, setStatusError] = useState(null);
    useEffect(() => {
        // Fetch both in parallel — they're independent. Status is cached
        // on the server side, session is a Redis lookup; both are fast.
        Promise.all([BootstrapApi.status(), SessionApi.info()])
            .then(([s, sess]) => {
            setStatus(s);
            setSession(sess);
        })
            .catch((err) => setStatusError(err instanceof Error ? err.message : 'Unknown error'))
            .finally(() => setLoading(false));
    }, []);
    if (loading) {
        return _jsx("div", { className: "card", children: _jsx("p", { children: "Loading\u2026" }) });
    }
    if (statusError) {
        return (_jsxs("div", { className: "card", children: [_jsx("h1", { children: "Cannot reach Akashic server" }), _jsx("p", { className: "error", children: statusError }), _jsxs("p", { className: "hint", children: ["Is the Akashic server running? Try", ' ', _jsx("code", { children: "docker compose --profile app up -d" }), "."] })] }));
    }
    // Bootstrap not yet complete → must finish that first.
    if (!status?.is_complete) {
        return _jsx(BootstrapForm, {});
    }
    // Bootstrap complete + logged in → show admin dashboard.
    if (session) {
        return _jsx(Dashboard, { session: session });
    }
    // Bootstrap complete + NOT logged in → invite to sign in.
    return (_jsxs("div", { className: "card", children: [_jsx("h1", { children: "Sign in to Akashic" }), _jsx("p", { children: "Bootstrap is complete. Sign in with the root account or an admin account." }), _jsxs("p", { className: "hint", children: ["Only users with role ", _jsx("code", { children: "root" }), " or ", _jsx("code", { children: "admin" }), " may access this console."] }), _jsx("div", { className: "actions", children: _jsx("a", { href: "/login", className: "primary", children: "Sign in" }) }), status && (_jsxs("details", { children: [_jsx("summary", { children: "Bootstrap details" }), _jsx(BootstrapAlreadyComplete, { status: status })] }))] }));
}
