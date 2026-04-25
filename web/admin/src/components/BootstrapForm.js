import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useState } from 'react';
import { BootstrapApi } from '../api/client';
/**
 * BootstrapForm — the only state-changing UI in Phase 6.
 *
 * The operator pastes the bootstrap token from server logs, fills in
 * their desired credentials, and submits. On success we reload the
 * page, which re-fetches status and shows the "already complete" view.
 */
export function BootstrapForm() {
    const [token, setToken] = useState('');
    const [username, setUsername] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [confirm, setConfirm] = useState('');
    const [error, setError] = useState(null);
    const [submitting, setSubmitting] = useState(false);
    async function onSubmit(e) {
        e.preventDefault();
        setError(null);
        // Client-side password match check before round-trip. The server
        // doesn't validate this -- it's purely a UX courtesy so the user
        // doesn't burn a rate-limit slot on a typo.
        if (password !== confirm) {
            setError('Passwords do not match.');
            return;
        }
        setSubmitting(true);
        try {
            await BootstrapApi.createRoot({ token, username, email, password });
            // Success: re-fetch status to flip the UI state. window.location
            // .reload() works fine here -- there's no in-flight state worth
            // preserving and a clean reload guarantees fresh CSRF cookie etc.
            window.location.reload();
        }
        catch (err) {
            setError(err instanceof Error ? err.message : 'Submission failed');
        }
        finally {
            setSubmitting(false);
        }
    }
    return (_jsxs("div", { className: "card", children: [_jsx("h1", { children: "Akashic Bootstrap" }), _jsx("p", { className: "subtitle", children: "Create the first root user for this Akashic deployment." }), _jsx("p", { className: "hint", children: "The bootstrap token is printed in the server logs on startup. Copy it from there and paste it below." }), _jsxs("form", { onSubmit: onSubmit, autoComplete: "off", children: [_jsxs("label", { children: [_jsx("span", { children: "Bootstrap token" }), _jsx("input", { type: "text", value: token, onChange: (e) => setToken(e.target.value.trim()), spellCheck: false, autoCapitalize: "off", placeholder: "64 hex characters from server logs", required: true, disabled: submitting })] }), _jsxs("label", { children: [_jsx("span", { children: "Username" }), _jsx("input", { type: "text", value: username, onChange: (e) => setUsername(e.target.value), spellCheck: false, autoCapitalize: "off", required: true, disabled: submitting })] }), _jsxs("label", { children: [_jsx("span", { children: "Email" }), _jsx("input", { type: "email", value: email, onChange: (e) => setEmail(e.target.value), required: true, disabled: submitting })] }), _jsxs("label", { children: [_jsx("span", { children: "Password" }), _jsx("input", { type: "password", value: password, onChange: (e) => setPassword(e.target.value), required: true, disabled: submitting })] }), _jsxs("label", { children: [_jsx("span", { children: "Confirm password" }), _jsx("input", { type: "password", value: confirm, onChange: (e) => setConfirm(e.target.value), required: true, disabled: submitting })] }), error && _jsx("div", { className: "error", role: "alert", children: error }), _jsx("button", { type: "submit", disabled: submitting, children: submitting ? 'Creating root user…' : 'Create root user' })] })] }));
}
