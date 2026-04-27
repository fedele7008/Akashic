// Phase 8 Chapter 2 placeholder. Chapter 4 replaces this with the
// real landing page (sign-up + sign-in entry points, branding,
// optional public client list).
//
// For now: an unstyled scaffold confirms the Next.js runtime is
// alive and reachable through the docker proxy.
export default function Home() {
  const brand = process.env.AKASHIC_PORTAL_BRAND_NAME ?? "Akashic";
  return (
    <main className="mx-auto max-w-2xl p-8">
      <h1 className="text-3xl font-semibold mb-4">{brand}</h1>
      <p className="text-[var(--text-muted)]">
        Tenant portal scaffold — Phase 8 Chapter 2.
      </p>
      <p className="mt-4 text-sm text-[var(--text-muted)]">
        Sign-up, sign-in, and developer surfaces land in chapters 4–6.
      </p>
    </main>
  );
}
