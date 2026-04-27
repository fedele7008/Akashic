/**
 * POST /api/auth/signup
 *
 * Public, no-auth signup. Validates the body against the same zod
 * schema the client uses, then forwards to the api server's
 * `POST /users/register` over plain HTTPS (no bearer needed — the
 * api server marks this endpoint as public).
 *
 * On 201 we return the standard envelope to the client; the FE
 * then redirects the browser to /api/auth/authorize so the user
 * lands signed in. We do NOT log the new user in directly here
 * (we'd have no access token without an OAuth round-trip).
 */

import { NextRequest, NextResponse } from "next/server";

import { apiCallPublic } from "../../../../server/api-client";
import { auditLog } from "../../../../server/audit";
import {
  SignUpSchema,
  normalizeSignUpInput,
  type SignUpInput,
} from "../../../../lib/validation";

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

  const parsed = SignUpSchema.safeParse(body);
  if (!parsed.success) {
    auditLog(req, "portal.signup.failure", {
      outcome: "fail",
      message: "client-side validation failed",
    });
    return NextResponse.json(
      {
        success: false,
        error: {
          code: "VALIDATION_FAILED",
          message: parsed.error.issues[0]?.message ?? "invalid input",
        },
      },
      { status: 400 },
    );
  }

  // Normalize the input and POST to the api server.
  const payload = normalizeSignUpInput(parsed.data as SignUpInput);
  const result = await apiCallPublic<unknown>("/users/register", {
    method: "POST",
    json: payload,
  });

  if (result.ok) {
    auditLog(req, "portal.signup.success", {
      outcome: "success",
      username: parsed.data.username,
      email: parsed.data.email,
    });
    return NextResponse.json(
      { success: true, data: result.data },
      { status: 201 },
    );
  }

  // Forward the api server's error code/message verbatim — the
  // client is built to recognize codes like USERNAME_TAKEN and
  // surface them on the right field.
  auditLog(req, "portal.signup.failure", {
    outcome: "fail",
    code: result.code,
    status: result.status,
    username: parsed.data.username,
  });
  return NextResponse.json(
    {
      success: false,
      error: { code: result.code, message: result.message, details: result.details },
    },
    { status: result.status },
  );
}
