/**
 * vpn-ip-rotator relay — исходящий прокси для агента, стоящего в России.
 *
 * Зачем: с российского хостинга api.telegram.org недоступен, а доступность
 * api.upcloud.com не гарантирована. Воркер даёт агенту выход к трём конкретным
 * API и больше ни к чему: список хостов зашит в код, это не open proxy.
 *
 * Секретов воркер не хранит — токены идут транзитом в заголовках самого запроса.
 * Развёртывание:  wrangler secret put RELAY_KEY  &&  wrangler deploy
 */

const UPSTREAMS = {
  tg: "https://api.telegram.org",
  uc: "https://api.upcloud.com",
  cf: "https://api.cloudflare.com",
};

// Заголовки, которые Cloudflare добавляет сам; вверх по течению они не нужны.
const STRIP = [
  "x-relay-key",
  "cf-connecting-ip",
  "cf-ipcountry",
  "cf-ray",
  "cf-visitor",
  "cf-worker",
  "x-forwarded-for",
  "x-forwarded-proto",
  "x-real-ip",
];

/** Сравнение без ранней остановки: не даёт подбирать ключ по таймингу. */
function secretsEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const segments = url.pathname.split("/").filter(Boolean);
    const prefix = segments[0];

    if (!secretsEqual(request.headers.get("X-Relay-Key") || "", env.RELAY_KEY || "")) {
      return new Response("forbidden\n", { status: 403 });
    }

    if (prefix === "healthz") {
      return new Response("ok\n", {
        status: 200,
        headers: { "content-type": "text/plain", "cache-control": "no-store" },
      });
    }

    const base = UPSTREAMS[prefix];
    if (!base) {
      return new Response(`unknown upstream: ${prefix || "(none)"}\n`, { status: 404 });
    }

    const target = new URL(base);
    target.pathname = "/" + segments.slice(1).join("/");
    target.search = url.search;

    const headers = new Headers(request.headers);
    for (const name of STRIP) headers.delete(name);
    headers.set("host", target.host);

    const hasBody = !["GET", "HEAD"].includes(request.method);

    try {
      const upstream = await fetch(target.toString(), {
        method: request.method,
        headers,
        body: hasBody ? request.body : undefined,
        redirect: "manual",
      });
      // Ответ отдаём как есть — агент сам разбирает коды и тела API.
      const out = new Headers(upstream.headers);
      out.delete("transfer-encoding");
      out.set("cache-control", "no-store");
      return new Response(upstream.body, { status: upstream.status, headers: out });
    } catch (err) {
      return new Response(`relay upstream error: ${err}\n`, { status: 502 });
    }
  },
};
