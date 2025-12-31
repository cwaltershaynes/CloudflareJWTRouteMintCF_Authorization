import { jwtVerify, createRemoteJWKSet } from "jose";

type Env = {
  // Cognito
  COGNITO_ISSUER: string; // e.g. https://cognito-idp.us-west-1.amazonaws.com/us-west-1_o09EFRG7u
  COGNITO_JWKS_URL: string; // e.g. https://cognito-idp.us-west-1.amazonaws.com/us-west-1_o09EFRG7u/.well-known/jwks.json
  COGNITO_CLIENT_ID: string; // your app client ID

  // SSO cookie name (must be Domain=.haynesconnect.com, Secure)
  SSO_COOKIE_NAME: string; // e.g. "hc_sso"

  // Where to send unauthenticated users
  APEX_LOGIN_URL: string; // e.g. https://haynesconnect.com/signin

  // JSON: {"sitea":["grp-sitea"],"pilot":["grp-pilot"],"*":["grp-any-authenticated"]}
  SITE_GROUP_MAP_JSON: string;

  // Optional: force HTTPS and strict host allowlist
  ALLOWED_HOST_SUFFIX: string; // e.g. ".haynesconnect.com"

  // Optional: bind KV for caching (recommended). If you don’t want KV, remove references.
  KV?: KVNamespace;
};

function getCookie(req: Request, name: string): string | null {
  const cookie = req.headers.get("Cookie");
  if (!cookie) return null;
  const parts = cookie.split(";").map((p) => p.trim());
  for (const p of parts) {
    if (p.startsWith(name + "=")) return decodeURIComponent(p.slice(name.length + 1));
  }
  return null;
}

function buildSetCookie(
  name: string,
  value: string,
  opts: {
    domain: string;
    path?: string;
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: "Lax" | "Strict" | "None";
    maxAge?: number;
    expires?: Date;
  }
) {
  const segs: string[] = [];
  segs.push(`${name}=${encodeURIComponent(value)}`);
  segs.push(`Domain=${opts.domain}`);
  segs.push(`Path=${opts.path ?? "/"}`);
  if (opts.httpOnly ?? true) segs.push("HttpOnly");
  if (opts.secure ?? true) segs.push("Secure");
  segs.push(`SameSite=${opts.sameSite ?? "Lax"}`);
  if (opts.maxAge != null) segs.push(`Max-Age=${opts.maxAge}`);
  if (opts.expires) segs.push(`Expires=${opts.expires.toUTCString()}`);
  return segs.join("; ");
}

function jsonResponse(status: number, obj: unknown) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function redirect(to: string, status = 302) {
  return new Response(null, { status, headers: { Location: to } });
}

function getSiteKeyFromHost(host: string): string {
  // sitea.haynesconnect.com -> "sitea"
  const first = host.split(".")[0] ?? "";
  return first.toLowerCase();
}

function parseGroupsFromClaims(claims: any): string[] {
  // Cognito commonly uses "cognito:groups" for group claims
  const g = claims["cognito:groups"];
  if (!g) return [];
  if (Array.isArray(g)) return g.map(String);
  // Sometimes it arrives as a string
  return [String(g)];
}

function isLogoutPath(url: URL): boolean {
  // Choose one canonical path on apex and subdomains
  return url.pathname === "/logout" || url.pathname === "/sso/logout";
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);
    const host = url.hostname.toLowerCase();

    // Enforce allowed suffix (basic safety)
    if (!host.endsWith(env.ALLOWED_HOST_SUFFIX)) {
      return jsonResponse(400, { error: "invalid_host" });
    }

    // Optional: handle SSO logout at edge for subdomains
    if (isLogoutPath(url)) {
      // Clear SSO cookie across all subdomains
      const res = redirect(`${env.APEX_LOGIN_URL}`, 302);
      res.headers.append(
        "Set-Cookie",
        buildSetCookie(env.SSO_COOKIE_NAME, "", {
          domain: env.ALLOWED_HOST_SUFFIX,
          maxAge: 0,
          expires: new Date(0),
          sameSite: "Lax",
        })
      );
      return res;
    }

    const token = getCookie(req, env.SSO_COOKIE_NAME);
    if (!token) {
      // Redirect to apex login with return URL
      const next = encodeURIComponent(url.toString());
      return redirect(`${env.APEX_LOGIN_URL}?next=${next}`, 302);
    }

    // Verify Cognito JWT using JWKS
    const JWKS = createRemoteJWKSet(new URL(env.COGNITO_JWKS_URL));
    let claims: any;
    try {
      const { payload } = await jwtVerify(token, JWKS, {
        issuer: env.COGNITO_ISSUER,
        audience: env.COGNITO_CLIENT_ID,
      });
      claims = payload;
    } catch (e: any) {
      // Token invalid/expired -> force login
      const next = encodeURIComponent(url.toString());
      return redirect(`${env.APEX_LOGIN_URL}?next=${next}`, 302);
    }

    // Authorization: map hostname -> allowed groups
    const siteKey = getSiteKeyFromHost(host);
    let map: Record<string, string[]> = {};
    try {
      map = JSON.parse(env.SITE_GROUP_MAP_JSON);
    } catch {
      return jsonResponse(500, { error: "bad_SITE_GROUP_MAP_JSON" });
    }

    const required = map[siteKey] ?? map["*"] ?? [];
    const userGroups = parseGroupsFromClaims(claims);

    if (required.length > 0) {
      const ok = required.some((g) => userGroups.includes(g));
      if (!ok) {
        return new Response("Forbidden", { status: 403 });
      }
    }

    // Forward request to origin (Tunnel/whatever your DNS points to).
    // Worker runs on the same hostname, so fetch(req) will continue to CF edge/origin routing.
    // Usually you want to pass through unchanged:
    return fetch(req);
  },
};
