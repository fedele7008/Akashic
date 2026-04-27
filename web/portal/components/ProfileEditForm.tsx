"use client";

/**
 * Profile editor — inline form for `display_name` + `email`. Submits
 * `PATCH /api/users/me`. On success, calls router.refresh() so the
 * server-rendered profile fields reflect the new values without a
 * hard reload.
 *
 * Username is intentionally not editable (LDAP `uid` is the user's
 * identity key in Akashic; renaming it would break audit trails).
 */

import { useRouter } from "next/navigation";
import { useState } from "react";
import { z } from "zod";

import { Button } from "./ui/Button";
import { Input } from "./ui/Input";
import { postJson } from "../lib/csrf-client";

interface ProfileEditFormProps {
  initialDisplayName: string;
  initialEmail: string;
}

const PatchSchema = z.object({
  display_name: z.string().trim().min(1).max(120),
  email: z.string().trim().email(),
});

interface FieldErrors {
  display_name?: string;
  email?: string;
}

interface PatchResponse {
  success?: boolean;
  data?: { updated?: boolean };
  error?: { code: string; message: string };
}

// PATCH /users/me uses fetch with method override for CSRF-aware calls;
// postJson hard-codes POST so we wrap our own fetch here.
async function patchJson(url: string, body: unknown) {
  const { readCsrfCookie, CSRF_HEADER_NAME } = await import("../lib/csrf-client");
  // Bootstrap if needed.
  let token = readCsrfCookie();
  if (!token) {
    await fetch("/api/health", { credentials: "same-origin" });
    token = readCsrfCookie();
  }
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers[CSRF_HEADER_NAME] = token;
  const res = await fetch(url, {
    method: "PATCH",
    headers,
    body: JSON.stringify(body),
    credentials: "same-origin",
  });
  let parsed: PatchResponse | null = null;
  try {
    parsed = (await res.json()) as PatchResponse;
  } catch {
    /* non-JSON */
  }
  return { ok: res.ok, status: res.status, body: parsed };
}

export function ProfileEditForm({ initialDisplayName, initialEmail }: ProfileEditFormProps) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [topMsg, setTopMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setTopMsg(null);
    setFieldErrors({});

    const data = new FormData(e.currentTarget);
    const candidate = {
      display_name: String(data.get("display_name") ?? ""),
      email: String(data.get("email") ?? ""),
    };
    const parsed = PatchSchema.safeParse(candidate);
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

    // Send only the fields that actually changed — minimises
    // unnecessary LDAP modifies.
    const diff: Record<string, string> = {};
    if (parsed.data.display_name !== initialDisplayName) diff.display_name = parsed.data.display_name;
    if (parsed.data.email !== initialEmail) diff.email = parsed.data.email;
    if (Object.keys(diff).length === 0) {
      setTopMsg({ kind: "ok", text: "Nothing changed." });
      setBusy(false);
      return;
    }

    const r = await patchJson("/api/users/me", diff);
    if (r.ok && r.body?.success) {
      setTopMsg({ kind: "ok", text: "Profile updated." });
      router.refresh();
    } else {
      setTopMsg({
        kind: "err",
        text: r.body?.error?.message ?? "Update failed. Please retry.",
      });
    }
    setBusy(false);
  }

  return (
    <form onSubmit={onSubmit} noValidate className="flex flex-col gap-4">
      {topMsg ? (
        <div
          role="status"
          className={
            topMsg.kind === "ok"
              ? "rounded-md border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-200"
              : "rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-200"
          }
        >
          {topMsg.text}
        </div>
      ) : null}

      <Input
        name="display_name"
        label="Display name"
        defaultValue={initialDisplayName}
        autoComplete="name"
        required
        error={fieldErrors.display_name}
      />

      <Input
        name="email"
        type="email"
        label="Email"
        defaultValue={initialEmail}
        autoComplete="email"
        required
        error={fieldErrors.email}
      />

      <Button type="submit" loading={busy}>
        Save changes
      </Button>
    </form>
  );
}
