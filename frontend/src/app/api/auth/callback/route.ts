import { BACKEND_HOST, BACKEND_PORT } from "@/app/model";

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

  if (opts.maxAge !== undefined) {
    str += `; Max-Age=${Math.floor(opts.maxAge)}`;
  }
  if (opts.expires) {
    str += `; Expires=${opts.expires.toUTCString()}`;
  }
  if (opts.httpOnly) str += `; HttpOnly`;
  if (opts.secure) str += `; Secure`;
  if (opts.path) str += `; Path=${opts.path}`;
  if (opts.sameSite) str += `; SameSite=${opts.sameSite}`;
  return str;
}

export async function GET(req: Request) {
  try {
    const url = new URL(req.url);
    const code = url.searchParams.get("code");

    if (!code) {
      console.log("Failed to get authorization code.");
      // redirect back to root
      const redirectUrl = new URL("/", url).toString();
      return Response.redirect(redirectUrl);
    }

    console.log("Authorization code received: " + code);

    const authServerUrl = `http://${BACKEND_HOST}:${BACKEND_PORT}/auth/token`;

    // 서버 사이드에서 Basic 인코딩 (브라우저 btoa 사용하지 않음)
    const basicValue = Buffer.from("parent").toString("base64");
    const resp = await fetch(authServerUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Basic ${basicValue}`,
      },
      body: JSON.stringify({ code }),
    });

    console.log("Response received:", resp.status);

    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      console.error("Token exchange failed:", resp.status, text);
      // 실패 시 리다이렉트
      const redirectUrl = new URL("/", url).toString();
      return Response.redirect(redirectUrl);
    }

    const data = await resp.json().catch(() => ({} as any));
    const access_token = typeof data?.access_token === "string" ? data.access_token : undefined;
    const expires_in = typeof data?.expires_in === "number" ? data.expires_in : 3600;

    if (!access_token) {
      console.error("Token response missing access_token:", data);
      const redirectUrl = new URL("/", url).toString();
      return Response.redirect(redirectUrl);
    }

    // cookie 옵션
    const isProd = process.env.NODE_ENV === "production";
    const cookieOpts = {
      maxAge: expires_in,
      httpOnly: false,
      secure: isProd,
      path: "/",
      sameSite: "None" as "Lax" | "Strict" | "None",
    };

    const cookieStr = serializeCookie("access_token", access_token, cookieOpts);
    console.log("Set access_token cookie:", cookieStr);
    // redirect with Set-Cookie header
    const redirectUrl = new URL("/", url).toString();
    const headers = new Headers({
      Location: redirectUrl,
      "Set-Cookie": `access_token=${access_token}; Path=/`,
    });

    return new Response(null, { status: 302, headers });
  } catch (error) {
    console.error(error);
    const redirectUrl = new URL("/", req.url).toString();
    return Response.redirect(redirectUrl);
  }
}