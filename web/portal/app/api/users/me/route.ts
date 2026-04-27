/**
 * GET, PATCH /api/users/me
 *
 * Thin pass-through to the api server's `/users/me` endpoint. The
 * portal's job here is to:
 *   1. Read the user's bearer token from the portal session.
 *   2. Forward to api.akashic.local with the bearer header.
 *   3. Return the api server's envelope verbatim.
 *
 * No request transformation — the client posts whatever the api
 * server expects, and we just relay. CSRF is enforced at the
 * middleware layer (PATCH is state-changing).
 */

import { NextRequest, NextResponse } from "next/server";

import { apiCall } from "../../../../server/api-client";

export async function GET() {
  const result = await apiCall<unknown>("/users/me", { method: "GET", touch: false });
  return relay(result);
}

export async function PATCH(req: NextRequest) {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json(
      { success: false, error: { code: "INVALID_REQUEST", message: "body must be JSON" } },
      { status: 400 },
    );
  }
  const result = await apiCall<unknown>("/users/me", { method: "PATCH", json: body });
  return relay(result);
}

interface ApiOk {
  ok: true;
  status: number;
  data: unknown;
}
interface ApiErr {
  ok: false;
  status: number;
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

function relay(r: ApiOk | ApiErr): NextResponse {
  if (r.ok) {
    return NextResponse.json({ success: true, data: r.data }, { status: r.status });
  }
  return NextResponse.json(
    { success: false, error: { code: r.code, message: r.message, details: r.details } },
    { status: r.status },
  );
}
