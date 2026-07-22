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

function renderHandshakePage(kind, resultJson, statusText) {
  const safeStatus = statusText.replace(/[<>&]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;" }[c]));
  return `<!DOCTYPE html>
<html>
  <body>
    <p>${safeStatus}</p>
    <pre id="log" style="white-space: pre-wrap; font-size: 12px; background: #f0f0f0; padding: 12px;"></pre>
    <button type="button" id="close-btn" style="display: none;">Close window</button>
    <script>
      (function () {
        var logEl = document.getElementById("log");
        function log(text) {
          logEl.textContent += text + "\\n";
        }

        document.getElementById("close-btn").addEventListener("click", function () {
          window.close();
        });

        try {
          log("window.opener present: " + Boolean(window.opener));

          if (!window.opener) {
            log(
              "No opener window found. This page must open as a popup from the CMS admin " +
              "page - your browser likely blocked the popup or navigated in the same tab " +
              "instead of opening a new one. Allow popups for this site and try again."
            );
            document.getElementById("close-btn").style.display = "inline-block";
            return;
          }

          var handshakeDone = false;

          function receiveMessage(message) {
            log('received message from opener: "' + message.data + '" (origin ' + message.origin + ")");
            handshakeDone = true;
            try {
              window.opener.postMessage(
                "authorization:github:${kind}:" + ${JSON.stringify(resultJson)},
                message.origin
              );
              log("sent authorization:github:${kind} payload back to opener at " + message.origin);
            } catch (err) {
              log("ERROR sending payload back to opener: " + err.message);
              document.getElementById("close-btn").style.display = "inline-block";
              return;
            }
            window.removeEventListener("message", receiveMessage, false);
            log("Done. If the CMS window did not update, it rejected this payload (check its console).");
            document.getElementById("close-btn").style.display = "inline-block";
          }

          window.addEventListener("message", receiveMessage, false);
          log("posting authorizing:github to opener, opener.origin unknown from here (cross-origin)");
          window.opener.postMessage("authorizing:github", "*");

          setTimeout(function () {
            if (!handshakeDone) {
              log(
                "Didn't hear back from the CMS window after 8s. It may not be listening, " +
                "or a browser/extension is blocking postMessage."
              );
              document.getElementById("close-btn").style.display = "inline-block";
            }
          }, 8000);
        } catch (err) {
          log("UNCAUGHT ERROR: " + err.message);
          document.getElementById("close-btn").style.display = "inline-block";
        }
      })();
    </script>
  </body>
</html>`;
}

function renderSuccess(payloadJson) {
  return renderHandshakePage("success", payloadJson, "Completing login...");
}

function renderError(message) {
  const payloadJson = JSON.stringify({ message });
  return renderHandshakePage("error", payloadJson, "Login failed: " + message);
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
