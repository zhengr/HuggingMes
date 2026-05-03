addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event.request));
});

const PROXY_SHARED_SECRET = "";
const ALLOW_PROXY_ALL = false;
const ALLOWED_TARGETS = [
  "api.telegram.org",
  "discord.com",
  "discordapp.com",
  "gateway.discord.gg",
  "status.discord.com",
  "slack.com",
  "api.slack.com",
  "web.whatsapp.com",
  "graph.facebook.com",
  "graph.instagram.com",
  "api.openai.com",
  "googleapis.com",
  "google.com",
  "googleusercontent.com",
  "gstatic.com",
];

function isAllowedHost(hostname) {
  const normalized = String(hostname || "").trim().toLowerCase();
  if (!normalized) return false;
  if (ALLOW_PROXY_ALL) return true;
  return ALLOWED_TARGETS.some((domain) => normalized === domain || normalized.endsWith(`.${domain}`));
}

async function handleRequest(request) {
  const url = new URL(request.url);
  const queryTarget = url.searchParams.get("proxy_target");
  const targetHost = request.headers.get("x-target-host") || queryTarget;
  const telegramStylePath = url.pathname.startsWith("/bot") || url.pathname.startsWith("/file/bot");

  if (PROXY_SHARED_SECRET) {
    const providedSecret = request.headers.get("x-proxy-key") || url.searchParams.get("proxy_key") || "";
    if (providedSecret !== PROXY_SHARED_SECRET && !(telegramStylePath && !targetHost)) {
      return new Response("Unauthorized: Invalid proxy key", { status: 401 });
    }
  }

  let targetBase = "";
  if (targetHost) {
    if (!isAllowedHost(targetHost)) {
      return new Response(`Forbidden: Host ${targetHost} is not allowed.`, { status: 403 });
    }
    targetBase = `https://${targetHost}`;
  } else if (telegramStylePath) {
    targetBase = "https://api.telegram.org";
  } else {
    return new Response("Invalid request: No target host provided.", { status: 400 });
  }

  const cleanSearch = new URLSearchParams(url.search);
  cleanSearch.delete("proxy_target");
  cleanSearch.delete("proxy_key");
  const searchStr = cleanSearch.toString();
  const targetUrl = targetBase + url.pathname + (searchStr ? `?${searchStr}` : "");

  const headers = new Headers(request.headers);
  for (const header of ["cf-connecting-ip", "cf-ray", "cf-visitor", "host", "x-real-ip", "x-target-host", "x-proxy-key"]) {
    headers.delete(header);
  }

  try {
    return await fetch(new Request(targetUrl, {
      method: request.method,
      headers,
      body: request.body,
      redirect: "follow",
    }));
  } catch (error) {
    return new Response(`Proxy Error: ${error.message}`, { status: 502 });
  }
}
