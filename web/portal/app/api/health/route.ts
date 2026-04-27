import { NextResponse } from "next/server";

// Liveness probe. Used by docker (and any future orchestrator) to
// know the portal process is alive. Doesn't reach any backend deps —
// just confirms the Next.js runtime is serving requests.
//
// Any deeper health-checking (e.g. "can I reach the akashic control
// plane?") goes in a separate /api/ready route in Chapter 3, when
// the mTLS client lands. Keeping liveness and readiness separate
// is the standard k8s pattern: liveness "is this process alive?",
// readiness "is this process ready to take traffic?".
export async function GET() {
  return NextResponse.json({
    service: "tenant-portal",
    status: "healthy",
  });
}
