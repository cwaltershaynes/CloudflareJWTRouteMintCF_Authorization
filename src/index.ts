import { jwtVerify, createRemoteJWKSet } from "jose";

const REGION = "us-west-1";
const USER_POOL_ID = "us-west-1_o09EFRG7u";
const APP_CLIENT_ID = "1k2p3d60uquup4imrll2d1b13p";

const ISSUER = `https://cognito-idp.${REGION}.amazonaws.com/${USER_POOL_ID}`;
const JWKS = createRemoteJWKSet(new URL(`${ISSUER}/.well-known/jwks.json`));

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(new RegExp(`(?:^|; )${name}=([^;]+)`));
  return match ? decodeURIComponent(match[1]) : null;
}

function redirectToLogin(request) {
  const url = new URL(request.url);
  const login = new URL("https://haynesconnect.com/login");
  login.searchParams.set("returnTo", url.toString());
  return Response.redirect(login.toString(), 302);
}

function parseAllowedHosts(payload) {
  const raw = payload["custom:allowed_hosts"];
  if (!raw) return [];
  return raw.split(",").map(h => h.trim().toLowerCase());
}

export default {
  async fetch(request) {

    const url = new URL(request.url);
    const hostname = url.hostname.toLowerCase();

    const token = getCookie(request, "hc_session");

    if (!token) {
      return redirectToLogin(request);
    }

    try {

      const { payload } = await jwtVerify(token, JWKS, {
        issuer: ISSUER,
        audience: APP_CLIENT_ID,
      });

      if (payload.token_use !== "id") {
        return redirectToLogin(request);
      }

      const allowedHosts = parseAllowedHosts(payload);

      if (!allowedHosts.includes(hostname)) {
        return new Response("Forbidden", { status: 403 });
      }

      const modifiedRequest = new Request(request);

      modifiedRequest.headers.set(
        "X-HC-User-Email",
        payload.email || ""
      );

      modifiedRequest.headers.set(
        "X-HC-User-Sub",
        payload.sub || ""
      );

      return fetch(modifiedRequest);

    } catch (err) {
      return redirectToLogin(request);
    }
  }
};
