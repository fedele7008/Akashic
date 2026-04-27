/**
 * /profile — read + edit profile.
 *
 * Server component: fetches `/users/me` from the api server using
 * the bearer-token client-helper, renders read-only details +
 * embeds a client-side edit form for the mutable fields.
 *
 * If the api server returns 401 (token expired between layout's
 * touchSession and this fetch), we surface a "session expired"
 * note rather than crashing the render. The user can click sign-out
 * and back in.
 */

import Link from "next/link";

import { ProfileEditForm } from "../../../components/ProfileEditForm";
import { apiCall } from "../../../server/api-client";

interface UserProfile {
  id: string;
  username: string;
  email: string;
  display_name: string;
  user_type: "user" | "admin" | "root";
  email_verified: boolean;
  last_login_at: string | null;
  created_at: string;
}

export const dynamic = "force-dynamic";

export default async function ProfilePage() {
  const result = await apiCall<UserProfile>("/users/me", { method: "GET", touch: false });

  if (!result.ok) {
    return (
      <section className="mx-auto max-w-xl px-4 py-12">
        <h1 className="mb-3 text-2xl font-semibold">Profile</h1>
        <div className="rounded-md border border-red-500/40 bg-red-500/10 p-4 text-sm text-red-200">
          <p className="font-medium">Couldn’t load profile.</p>
          <p className="mt-1 text-red-300/80">
            {result.code}: {result.message}
          </p>
          <p className="mt-2 text-red-300/60">
            <Link href="/api/auth/logout" className="underline">
              Sign out
            </Link>{" "}
            and try again.
          </p>
        </div>
      </section>
    );
  }

  const u = result.data;

  return (
    <section className="mx-auto flex max-w-xl flex-col gap-8 px-4 py-12">
      <header>
        <h1 className="text-2xl font-semibold">Your profile</h1>
        <p className="mt-1 text-sm text-[var(--text-muted)]">
          Identity backed by your operator’s LDAP directory.
        </p>
      </header>

      <dl className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-3">
        <ReadOnlyField label="Username" value={u.username} />
        <ReadOnlyField label="User type" value={prettyUserType(u.user_type)} />
        <ReadOnlyField label="Created" value={formatDate(u.created_at)} />
        <ReadOnlyField
          label="Last login"
          value={u.last_login_at ? formatDate(u.last_login_at) : "—"}
        />
      </dl>

      <div className="flex flex-col gap-4">
        <h2 className="text-base font-semibold">Editable fields</h2>
        <ProfileEditForm initialDisplayName={u.display_name} initialEmail={u.email} />
      </div>

      <div className="flex items-center justify-between rounded-md border border-[var(--text-muted)]/20 bg-[var(--card)] p-4 text-sm">
        <div>
          <p className="font-medium">Change password</p>
          <p className="text-[var(--text-muted)]">
            Updates your password in the directory.
          </p>
        </div>
        <Link
          href="/profile/password"
          className="rounded-md border border-[var(--text-muted)]/30 px-3 py-1.5 hover:bg-[var(--bg)]"
        >
          Open
        </Link>
      </div>
    </section>
  );
}

function ReadOnlyField({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-[var(--text-muted)]/20 bg-[var(--card)] p-3">
      <dt className="text-xs uppercase tracking-wide text-[var(--text-muted)]">{label}</dt>
      <dd className="mt-1 break-words text-[var(--text)]">{value}</dd>
    </div>
  );
}

function prettyUserType(t: string): string {
  if (t === "user") return "Standard";
  return t.charAt(0).toUpperCase() + t.slice(1);
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}
