import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
/**
 * Shown after bootstrap is complete. Phase 6 has no login flow yet;
 * this view tells the operator "the bootstrap form is permanently
 * closed; further user management is via akashic-cli for now". Phase
 * 7 will replace this with a redirect to /login.
 */
export function BootstrapAlreadyComplete({ status }) {
    return (_jsxs("div", { className: "card", children: [_jsx("h1", { children: "Akashic \u2014 Bootstrap Complete" }), _jsx("p", { className: "subtitle", children: "This deployment has already been bootstrapped." }), status.completed_at && (_jsxs("p", { children: ["Completed at: ", _jsx("code", { children: status.completed_at })] })), _jsx("hr", {}), _jsx("h2", { children: "What's next?" }), _jsxs("p", { children: ["The web-based admin dashboard is coming in a future phase. For now, manage users via the ", _jsx("code", { children: "akashic-cli" }), ":"] }), _jsx("pre", { children: `# Check server status
akashic-cli bootstrap status

# Create additional admin users (Phase 7+)
# (currently only the root user exists)` })] }));
}
