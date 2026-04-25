import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useEffect, useState } from 'react';
import { BootstrapApi } from './api/client';
import { BootstrapForm } from './components/BootstrapForm';
import { BootstrapAlreadyComplete } from './components/BootstrapAlreadyComplete';
/**
 * App is a tiny two-state shell:
 *   loading       → spinner
 *   is_complete   → BootstrapAlreadyComplete
 *   otherwise     → BootstrapForm
 *
 * No router (only one page in Phase 6), no auth context (no login
 * yet), no state library. Phase 7 expands this into a proper SPA.
 */
export function App() {
    const [status, setStatus] = useState(null);
    const [loading, setLoading] = useState(true);
    const [statusError, setStatusError] = useState(null);
    useEffect(() => {
        BootstrapApi.status()
            .then(setStatus)
            .catch((err) => setStatusError(err instanceof Error ? err.message : 'Unknown error'))
            .finally(() => setLoading(false));
    }, []);
    if (loading) {
        return _jsx("div", { className: "card", children: _jsx("p", { children: "Loading\u2026" }) });
    }
    if (statusError) {
        return (_jsxs("div", { className: "card", children: [_jsx("h1", { children: "Cannot reach Akashic server" }), _jsx("p", { className: "error", children: statusError }), _jsxs("p", { className: "hint", children: ["Is the Akashic server running? Try", ' ', _jsx("code", { children: "docker compose --profile app up -d" }), "."] })] }));
    }
    if (status?.is_complete) {
        return _jsx(BootstrapAlreadyComplete, { status: status });
    }
    return _jsx(BootstrapForm, {});
}
