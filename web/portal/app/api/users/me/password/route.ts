/**
 * POST /api/users/me/password
 *
 * Pass-through to the api server's `/users/me/password`. Body:
 * `{ old_password, new_password }`. The api server enforces the
 * password policy and verifies the old password by binding to LDAP
 * — we just relay.
 */

import { NextRequest, NextResponse } from "next/server";

import { apiCall } from "../../../../../server/api-client";

export async function POST(req: NextRequest) {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json(
      { success: false, error: { code: "INVALID_REQUEST", message: "body must be JSON" } },
      { status: 400 },
    );
  }
  const r = await apiCall<unknown>("/users/me/password", { method: "POST", json: body });
  if (r.ok) {
    return NextResponse.json({ success: true, data: r.data }, { status: r.status });
  }
  return NextResponse.json(
    { success: false, error: { code: r.code, message: r.message, details: r.details } },
    { status: r.status },
  );
}
