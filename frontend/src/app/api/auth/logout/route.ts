function serializeCookie(
  name: string,
  value: string,
  opts: {
    maxAge?: number;
    expires?: Date;
    httpOnly?: boolean;
    secure?: boolean;
    path?: string;
    sameSite?: "Lax" | "Strict" | "None";
  } = {}
) {
  let str = `${encodeURIComponent(name)}=${encodeURIComponent(value)}`;
  if (opts.maxAge !== undefined) str += `; Max-Age=${Math.floor(opts.maxAge)}`;
  if (opts.expires) str += `; Expires=${opts.expires.toUTCString()}`;
  if (opts.httpOnly) str += `; HttpOnly`;
  if (opts.secure) str += `; Secure`;
  if (opts.path) str += `; Path=${opts.path}`;
  if (opts.sameSite) str += `; SameSite=${opts.sameSite}`;
  return str;
}

export async function POST(req: Request) {
  try {
    const isProd = process.env.NODE_ENV === "production";
    const expires = new Date(0); // 1970 epoch -> 만료시켜 삭제

    const cookieOpts = {
      httpOnly: true,
      secure: isProd,
      path: "/",
      sameSite: "Lax" as "Lax" | "Strict" | "None",
      expires,
      maxAge: 0,
    };

    const cookies = [
      `access_token=; Path=/; expires=${expires.toUTCString()}; max-age=0`,
    ];

    const headers = new Headers({
      "Content-Type": "application/json",
    });
    // 여러 Set-Cookie 필요하므로 append
    cookies.forEach((c) => headers.append("Set-Cookie", c));

    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers,
    });
  } catch (err) {
    console.error("logout error:", err);
    return new Response(JSON.stringify({ ok: false, error: "internal_error" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
}
