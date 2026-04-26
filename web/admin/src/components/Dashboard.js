import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useState } from 'react';
import { SessionApi } from '../api/client';
/**
 * Dashboard is the placeholder logged-in view for Phase 7. It just
 * shows who is logged in and a logout button. The real admin
 * dashboard (clients, users, policies, audit) is Phase 8+.
 *
 * Why a placeholder lands now: Step 9 of Phase 7 wires up the OAuth
 * flow end-to-end. Without *some* logged-in surface to land on, we
 * can't visually confirm the flow worked. A minimal page is enough
 * to prove out the redirect/cookie/role-check chain.
 */
export function Dashboard({ session }) {
    const [loggingOut, setLoggingOut] = useState(false);
    const handleLogout = async () => {
        setLoggingOut(true);
        let authLogoutUrl = '';
        try {
            authLogoutUrl = await SessionApi.logout();
        }
        catch {
            // Even on logout error, navigate — the user wants OUT. Falling
            // back to '/' means the BFF session may already be cleared but
            // the auth-server session might survive; a future fresh login
            // would be silent. Acceptable degraded behavior compared to
            // "the button did nothing."
        }
        // If we got an auth_logout_url, navigate there. The auth-server
        // will clear ITS session and redirect the browser back to /,
        // landing on the App shell which re-renders the sign-in landing.
        // Without this hop, the auth-server's IdP session would persist
        // and the next Sign-in click would auto-log-in silently — which
        // is exactly the SSO behavior we DON'T want after explicit logout.
        window.location.href = authLogoutUrl || '/';
    };
    return (_jsxs("div", { className: "card", children: [_jsx("h1", { children: "Akashic admin console" }), _jsxs("p", { className: "hint", children: ["You're logged in as ", _jsx("strong", { children: session.username || session.user_id }), ' ', "(", session.user_type, ")."] }), _jsxs("dl", { className: "kv", children: [_jsx("dt", { children: "User ID" }), _jsx("dd", { children: _jsx("code", { children: session.user_id }) }), _jsx("dt", { children: "Email" }), _jsx("dd", { children: session.email || _jsx("span", { className: "hint", children: "(not set)" }) }), _jsx("dt", { children: "Session issued" }), _jsx("dd", { children: new Date(session.issued_at).toLocaleString() }), _jsx("dt", { children: "Session expires" }), _jsx("dd", { children: new Date(session.expires_at).toLocaleString() })] }), _jsx("p", { className: "hint", children: "Phase 7.5 dashboard coming soon \u2014 client management, user administration, audit log viewer." }), _jsx("div", { className: "actions", children: _jsx("button", { onClick: handleLogout, disabled: loggingOut, className: "secondary", children: loggingOut ? 'Logging out…' : 'Log out' }) })] }));
}
