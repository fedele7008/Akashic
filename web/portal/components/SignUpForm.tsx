"use client";

/**
 * Sign-up form. Client component because we need:
 *   - per-field validation feedback (zod, mirrors server schema)
 *   - the X-Akashic-CSRF header (read from the JS-readable cookie)
 *   - "loading" state on the submit button
 *
 * On success, redirects the browser to /api/auth/authorize so the
 * user lands signed in immediately. (Phase 8 has no email-verification
 * gate; Phase 9 changes this to "show a check-your-email" page.)
 */

import { useId, useState } from "react";

import { Button } from "./ui/Button";
import { Input } from "./ui/Input";
import { postJson } from "../lib/csrf-client";
import { SignUpSchema, normalizeSignUpInput, type SignUpInput } from "../lib/validation";

interface FieldErrors {
  username?: string;
  email?: string;
  password?: string;
  display_name?: string;
}

interface SignupResponse {
  success?: boolean;
  data?: { user: { id: string; username: string; email: string; ldap_dn: string } };
  error?: { code: string; message: string; details?: Record<string, unknown> };
}

export function SignUpForm() {
  const formId = useId();
  const [busy, setBusy] = useState(false);
  const [topError, setTopError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setTopError(null);
    setFieldErrors({});

    const data = new FormData(e.currentTarget);
    const raw: SignUpInput = {
      username: String(data.get("username") ?? ""),
      email: String(data.get("email") ?? ""),
      password: String(data.get("password") ?? ""),
      display_name: String(data.get("display_name") ?? ""),
    };

    const parsed = SignUpSchema.safeParse(raw);
    if (!parsed.success) {
      const fe: FieldErrors = {};
      for (const issue of parsed.error.issues) {
        const key = issue.path[0] as keyof FieldErrors;
        if (!fe[key]) fe[key] = issue.message;
      }
      setFieldErrors(fe);
      setBusy(false);
      return;
    }

    const res = await postJson<SignupResponse>(
      "/api/auth/signup",
      normalizeSignUpInput(parsed.data),
    );

    if (res.ok && res.body?.success) {
      // Hand off to OAuth — the user will round-trip through the auth
      // server and land back on /api/auth/callback signed in.
      window.location.href = "/api/auth/authorize";
      return;
    }

    // Surface the api server's error code to the user.
    const code = res.body?.error?.code ?? "UNKNOWN";
    const message = res.body?.error?.message ?? "Sign-up failed. Please try again.";

    if (code === "USERNAME_TAKEN") {
      setFieldErrors({ username: "That username is already taken." });
    } else if (code === "PASSWORD_POLICY_VIOLATION") {
      setFieldErrors({ password: message });
    } else if (code === "VALIDATION_FAILED") {
      // The api server's validation messages aren't field-keyed, so
      // surface as top-level — the user can re-read the field hints.
      setTopError(message);
    } else if (code === "BOOTSTRAP_INCOMPLETE") {
      // Operator hasn't finished mint-the-root-user yet. Stronger
      // wording than the api server's stock message — this isn't a
      // user-fixable problem.
      setTopError(
        "This deployment is still being set up by its operator. Sign-up will be available once initial setup is complete.",
      );
    } else {
      setTopError(message);
    }
    setBusy(false);
  }

  return (
    <form
      id={formId}
      onSubmit={handleSubmit}
      noValidate
      className="flex flex-col gap-4"
      aria-busy={busy || undefined}
    >
      {topError ? (
        <div
          role="alert"
          className="rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-200"
        >
          {topError}
        </div>
      ) : null}

      <Input
        name="username"
        label="Username"
        autoComplete="username"
        required
        error={fieldErrors.username}
        hint="3–64 characters. Letters, numbers, dots, underscores, dashes."
      />

      <Input
        name="email"
        type="email"
        label="Email"
        autoComplete="email"
        required
        error={fieldErrors.email}
      />

      <Input
        name="password"
        type="password"
        label="Password"
        autoComplete="new-password"
        required
        minLength={8}
        error={fieldErrors.password}
        hint="At least 8 characters."
      />

      <Input
        name="display_name"
        label="Display name (optional)"
        autoComplete="name"
        error={fieldErrors.display_name}
        hint="Defaults to your username."
      />

      <Button type="submit" loading={busy}>
        Create account
      </Button>
    </form>
  );
}
