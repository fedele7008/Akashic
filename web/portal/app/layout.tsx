import type { Metadata } from "next";
import "./globals.css";

// Phase 8 Chapter 2: minimal root layout. Operator-rebrandable
// metadata (title, description) reads from env vars. Defaults are
// generic so an unconfigured deployment still renders something
// sensible. Chapter 4's landing page work will replace these
// placeholders with real branding.
export const metadata: Metadata = {
  title: process.env.AKASHIC_PORTAL_BRAND_NAME ?? "Akashic",
  description:
    process.env.AKASHIC_PORTAL_TAGLINE ??
    "Identity provider built on Akashic.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
