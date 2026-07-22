const GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token";
const OAUTH_SCOPE = "repo,user";
const STATE_COOKIE = "oauth_state";

function htmlResponse(body, status = 200) {
  return new Response(body, {
    status,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

function readCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  const match = header.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

async function handleAuth(request, env) {
  const state = crypto.randomUUID();
  const redirectUri = new URL("/callback", request.url).toString();

  const authorizeUrl = new URL(GITHUB_AUTHORIZE_URL);
  authorizeUrl.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
  authorizeUrl.searchParams.set("redirect_uri", redirectUri);
  authorizeUrl.searchParams.set("scope", OAUTH_SCOPE);
  authorizeUrl.searchParams.set("state", state);

  return new Response(null, {
    status: 302,
    headers: {
      Location: authorizeUrl.toString(),
      "Set-Cookie": `${STATE_COOKIE}=${state}; HttpOnly; Secure; SameSite=Lax; Max-Age=600; Path=/`,
    },
  });
}

async function handleCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const cookieState = readCookie(request, STATE_COOKIE);
  const clearCookie = `${STATE_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/`;

  if (!code || !state || !cookieState || state !== cookieState) {
    return htmlResponse(renderError("Invalid or expired login attempt. Close this window and try again."), 400);
  }

  let tokenResponse;
  try {
    tokenResponse = await fetch(GITHUB_TOKEN_URL, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        client_id: env.GITHUB_CLIENT_ID,
        client_secret: env.GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: new URL("/callback", request.url).toString(),
      }),
    });
  } catch (err) {
    return htmlResponse(renderError("Could not reach GitHub to complete login."), 502);
  }

  if (!tokenResponse.ok) {
    return htmlResponse(renderError("GitHub rejected the login attempt."), 502);
  }

  const data = await tokenResponse.json();
  if (!data.access_token) {
    return htmlResponse(renderError(data.error_description || "GitHub did not return an access token."), 502);
  }

  const payload = JSON.stringify({ token: data.access_token, provider: "github" });

  return new Response(renderSuccess(payload), {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "Set-Cookie": clearCookie,
    },
  });
}

function renderSuccess(payloadJson) {
  return `<!DOCTYPE html>
<html>
  <body>
    <script>
      (function () {
        function receiveMessage(message) {
          window.opener.postMessage(
            "authorization:github:success:" + ${JSON.stringify(payloadJson)},
            message.origin
          );
          window.removeEventListener("message", receiveMessage, false);
        }
        window.addEventListener("message", receiveMessage, false);
        window.opener.postMessage("authorizing:github", "*");
      })();
    </script>
    Login successful, this window can be closed.
  </body>
</html>`;
}

function renderError(message) {
  const safe = message.replace(/[<>&]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;" }[c]));
  return `<!DOCTYPE html>
<html>
  <body>
    <script>
      (function () {
        function receiveMessage(message) {
          window.opener.postMessage(
            "authorization:github:error:" + ${JSON.stringify(JSON.stringify({ }))},
            message.origin
          );
          window.removeEventListener("message", receiveMessage, false);
        }
        window.addEventListener("message", receiveMessage, false);
        window.opener.postMessage("authorizing:github", "*");
      })();
    </script>
    Login failed: ${safe}
  </body>
</html>`;
}

export default {
  async fetch(request, env) {
    if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET) {
      return new Response("OAuth proxy is missing GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET secrets.", { status: 500 });
    }

    const url = new URL(request.url);

    if (url.pathname === "/auth") {
      return handleAuth(request, env);
    }

    if (url.pathname === "/callback") {
      return handleCallback(request, env);
    }

    return new Response("Not found", { status: 404 });
  },
};
