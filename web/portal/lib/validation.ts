/**
 * Shared zod validation schemas.
 *
 * Used on both the server (POST handler input) and on the client
 * (form pre-submit checks). Keeping the schema in one place means
 * the two sides can never drift — if the server adds a constraint,
 * the client picks it up automatically.
 *
 * Note: client-side validation is a UX feature, not a security
 * feature. The server re-validates everything; client checks just
 * give the user immediate feedback.
 */

import { z } from "zod";

/**
 * Sign-up form input. Mirrors what `apiCallPublic` posts to the api
 * server's `POST /users/register`. The api server enforces the
 * authoritative password policy; we apply only basic length here so
 * the user gets a quick "too short" message before round-tripping
 * to the backend.
 */
export const SignUpSchema = z.object({
  username: z
    .string()
    .trim()
    .min(3, "Username must be at least 3 characters.")
    .max(64, "Username must be at most 64 characters.")
    .regex(/^[a-z0-9._-]+$/i, "Letters, numbers, dots, underscores, and dashes only."),
  email: z.string().trim().email("Enter a valid email address."),
  password: z
    .string()
    .min(8, "Password must be at least 8 characters.")
    .max(128, "Password must be at most 128 characters."),
  display_name: z
    .string()
    .trim()
    .max(120, "Display name must be at most 120 characters.")
    .optional()
    .or(z.literal("")),
});

export type SignUpInput = z.infer<typeof SignUpSchema>;

/**
 * Strip empty optional fields before sending to the api server. The
 * server treats omitted and empty-string differently for some fields
 * (display_name falls back to username only when omitted), so we
 * normalize on the client first.
 */
export function normalizeSignUpInput(input: SignUpInput): Record<string, string> {
  const out: Record<string, string> = {
    username: input.username,
    email: input.email,
    password: input.password,
  };
  if (input.display_name && input.display_name.length > 0) {
    out.display_name = input.display_name;
  }
  return out;
}
