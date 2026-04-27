"use client";

/**
 * Change-password client form. Three fields: old, new, confirm.
 * Confirm-match is checked client-side; password policy is enforced
 * server-side by the api server (errors surface as
 * `PASSWORD_POLICY_VIOLATION` and we display the message).
 *
 * On success: clear the inputs, show a success notice, link to
 * sign back in. We deliberately do NOT auto-redirect — a password
 * change is a security event the user should pause to absorb.
 */

import { useState } from "react";
import { z } from "zod";

import { Button } from "./ui/Button";
import { Input } from "./ui/Input";
import { postJson } from "../lib/csrf-client";

const ClientSchema = z
  .object({
    old_password: z.string().min(1, "Enter your current password."),
    new_password: z.string().min(8, "New password must be at least 8 characters."),
    confirm: z.string().min(1, "Confirm the new password."),
  })
  .refine((d) => d.new_password === d.confirm, {
    message: "Passwords do not match.",
    path: ["confirm"],
  });

interface FieldErrors {
  old_password?: string;
  new_password?: string;
  confirm?: string;
}

interface PasswordResponse {
  success?: boolean;
  data?: { updated?: boolean };
  error?: { code: string; message: string };
}

export function ChangePasswordForm() {
  const [busy, setBusy] = useState(false);
  const [topMsg, setTopMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});
  const [done, setDone] = useState(false);

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setTopMsg(null);
    setFieldErrors({});

    const form = new FormData(e.currentTarget);
    const candidate = {
      old_password: String(form.get("old_password") ?? ""),
      new_password: String(form.get("new_password") ?? ""),
      confirm: String(form.get("confirm") ?? ""),
    };
    const parsed = ClientSchema.safeParse(candidate);
    if (!parsed.success) {
      const fe: FieldErrors = {};
      for (const issue of parsed.error.issues) {
        const k = issue.path[0] as keyof FieldErrors;
        if (!fe[k]) fe[k] = issue.message;
      }
      setFieldErrors(fe);
      setBusy(false);
      return;
    }

    const res = await postJson<PasswordResponse>("/api/users/me/password", {
      old_password: parsed.data.old_password,
      new_password: parsed.data.new_password,
    });

    if (res.ok && res.body?.success) {
      setDone(true);
      setTopMsg({ kind: "ok", text: "Password updated." });
      setBusy(false);
      return;
    }

    const code = res.body?.error?.code ?? "UNKNOWN";
    const message = res.body?.error?.message ?? "Could not change password. Please retry.";

    if (code === "INVALID_CREDENTIALS") {
      setFieldErrors({ old_password: "That current password is incorrect." });
    } else if (code === "PASSWORD_POLICY_VIOLATION") {
      setFieldErrors({ new_password: message });
    } else {
      setTopMsg({ kind: "err", text: message });
    }
    setBusy(false);
  }

  if (done) {
    return (
      <div className="flex flex-col gap-3">
        <div
          role="status"
          className="rounded-md border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-200"
        >
          {topMsg?.text ?? "Password updated."}
        </div>
        <p className="text-sm text-[var(--text-muted)]">
          Your password is changed. You can keep using the portal — your
          existing session is still valid.
        </p>
      </div>
    );
  }

  return (
    <form onSubmit={onSubmit} noValidate className="flex flex-col gap-4">
      {topMsg ? (
        <div
          role="alert"
          className="rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-200"
        >
          {topMsg.text}
        </div>
      ) : null}

      <Input
        name="old_password"
        type="password"
        label="Current password"
        autoComplete="current-password"
        required
        error={fieldErrors.old_password}
      />

      <Input
        name="new_password"
        type="password"
        label="New password"
        autoComplete="new-password"
        required
        minLength={8}
        error={fieldErrors.new_password}
        hint="At least 8 characters."
      />

      <Input
        name="confirm"
        type="password"
        label="Confirm new password"
        autoComplete="new-password"
        required
        error={fieldErrors.confirm}
      />

      <Button type="submit" loading={busy}>
        Change password
      </Button>
    </form>
  );
}
