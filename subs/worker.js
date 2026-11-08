/**
 * Генератор подписок sing-box и страница инструкции.
 *
 * Почему Worker, а не скрипт на VPN-сервере: подписка живёт на edge Cloudflare,
 * поэтому доступна из России даже когда IP сервера заблокирован, и не раскрывает
 * этот IP. На сервере при этом не нужен ни веб-сервер, ни место на диске.
 *
 * Состояния не хранит: UUID в ссылке и есть ключ доступа. Угадавший UUID получит
 * конфиг, но подключиться по нему не сможет — пускает панель, а не Worker.
 *
 *   GET /                 страница с инструкцией для пользователя
 *   GET /sub/<uuid>       конфиг sing-box с белыми списками
 *   GET /vless/<uuid>     ссылка vless:// для Hiddify и v2rayNG
 */

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Правила маршрутизации для России. Наборы проверены на существование;
// geoip-private больше не выпускается — локальные сети ловим через ip_is_private.
const SRS = "https://raw.githubusercontent.com/SagerNet";
const RULE_SETS = [
  { tag: "ru-domains", url: `${SRS}/sing-geosite/rule-set/geosite-category-ru.srs` },
  { tag: "ru-yandex", url: `${SRS}/sing-geosite/rule-set/geosite-yandex.srs` },
  { tag: "ru-vk", url: `${SRS}/sing-geosite/rule-set/geosite-vk.srs` },
  { tag: "ru-sberbank", url: `${SRS}/sing-geosite/rule-set/geosite-sberbank.srs` },
  { tag: "ru-ips", url: `${SRS}/sing-geoip/rule-set/geoip-ru.srs` },
];
const RU_DOMAIN_TAGS = ["ru-domains", "ru-yandex", "ru-vk", "ru-sberbank"];

function singboxConfig(uuid, env) {
  const host = env.VPN_HOST;
  const port = Number(env.VPN_PORT || 443);

  return {
    log: { level: "warn" },

    dns: {
      // Русские домены резолвим напрямую у российского резолвера: иначе получим
      // ответы для европейской локации и медленный доступ к местным сервисам.
      servers: [
        { type: "udp", tag: "dns-proxy", server: "1.1.1.1", detour: "proxy" },
        { type: "udp", tag: "dns-direct", server: "77.88.8.8", detour: "direct" },
      ],
      rules: [{ rule_set: RU_DOMAIN_TAGS, action: "route", server: "dns-direct" }],
      final: "dns-proxy",
      strategy: "ipv4_only",
    },

    inbounds: [
      {
        type: "tun",
        tag: "tun-in",
        address: ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
        auto_route: true,
        strict_route: true,
      },
    ],

    outbounds: [
      {
        type: "vless",
        tag: "proxy",
        server: host,
        server_port: port,
        uuid,
        flow: "xtls-rprx-vision",
        tls: {
          enabled: true,
          server_name: env.VPN_SNI,
          utls: { enabled: true, fingerprint: env.VPN_FINGERPRINT || "chrome" },
          reality: {
            enabled: true,
            public_key: env.VPN_PUBLIC_KEY,
            short_id: env.VPN_SHORT_ID,
          },
        },
      },
      { type: "direct", tag: "direct" },
    ],

    route: {
      rules: [
        { action: "sniff" },
        { protocol: "dns", action: "hijack-dns" },
        // Локальная сеть — мимо туннеля, иначе отвалится доступ к роутеру и принтеру.
        { ip_is_private: true, action: "route", outbound: "direct" },
        // Банки, Госуслуги и прочее российское — напрямую, без VPN.
        { rule_set: [...RU_DOMAIN_TAGS, "ru-ips"], action: "route", outbound: "direct" },
      ],
      // download_detour: proxy — обязательно. raw.githubusercontent.com в России
      // блокируется, и напрямую правила просто не скачаются.
      //
      // Поле устарело в sing-box 1.14 и исчезнет в 1.16; замена —
      // http_client: { detour: "proxy" }. Менять пока нельзя: ядра до 1.14
      // ломаются на незнакомом поле — парсер строгий и отвергает профиль
      // целиком с «json: unknown field». Когда выйдет 1.16, поле придётся
      // выбирать по версии ядра, а не заменять механически. То же касается
      // experimental.cache_file.store_rdrc ниже.
      rule_set: RULE_SETS.map((r) => ({
        type: "remote",
        tag: r.tag,
        format: "binary",
        url: r.url,
        download_detour: "proxy",
        update_interval: "7d",
      })),
      final: "proxy",
      auto_detect_interface: true,
    },

    experimental: {
      cache_file: { enabled: true, store_rdrc: true },
    },
  };
}

function vlessLink(uuid, env, label) {
  const q = new URLSearchParams({
    type: "tcp",
    security: "reality",
    encryption: "none",
    pbk: env.VPN_PUBLIC_KEY,
    fp: env.VPN_FINGERPRINT || "chrome",
    sni: env.VPN_SNI,
    sid: env.VPN_SHORT_ID,
    spx: "/",
    flow: "xtls-rprx-vision",
  });
  return `vless://${uuid}@${env.VPN_HOST}:${env.VPN_PORT || 443}?${q}#${encodeURIComponent(label)}`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean);

    if (parts.length === 0) {
      return new Response(instructionPage(url.host), {
        headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
      });
    }

    const [kind, uuid] = parts;
    if (!UUID_RE.test(uuid || "")) {
      return new Response("not found\n", { status: 404 });
    }

    if (kind === "sub") {
      const body = JSON.stringify(singboxConfig(uuid.toLowerCase(), env), null, 2);
      return new Response(body, {
        headers: {
          "content-type": "application/json; charset=utf-8",
          "cache-control": "no-store",
          // Имя профиля в приложении и интервал обновления подписки.
          "profile-title": "VPN",
          "profile-update-interval": "24",
        },
      });
    }

    if (kind === "vless") {
      return new Response(vlessLink(uuid.toLowerCase(), env, "VPN") + "\n", {
        headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
      });
    }

    return new Response("not found\n", { status: 404 });
  },
};

/**
 * Страница для пользователя. Самодостаточная: ни внешних стилей, ни шрифтов,
 * ни скриптов — чтобы открывалась и там, где половина интернета недоступна.
 */
function instructionPage(host) {
  return `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Настройка VPN</title>
<style>
  :root{
    --bg:#f6f7f9; --card:#fff; --ink:#15181d; --dim:#5c6370;
    --line:#e3e6ea; --accent:#1d6fe0; --okbg:#eaf6ec; --okink:#1d6b32;
  }
  @media (prefers-color-scheme:dark){
    :root{ --bg:#14171c; --card:#1c2026; --ink:#e8eaed; --dim:#9aa2ae;
           --line:#2b313a; --accent:#6aa9f5; --okbg:#182a1d; --okink:#8fd3a0; }
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);
       font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
       padding:24px 16px 56px}
  main{max-width:620px;margin:0 auto}
  h1{font-size:26px;line-height:1.25;margin:0 0 6px}
  .lead{color:var(--dim);margin:0 0 28px}
  ol{list-style:none;counter-reset:s;padding:0;margin:0}
  li{counter-increment:s;background:var(--card);border:1px solid var(--line);
     border-radius:14px;padding:18px 18px 18px 60px;margin-bottom:12px;position:relative}
  li::before{content:counter(s);position:absolute;left:18px;top:17px;
     width:28px;height:28px;border-radius:50%;background:var(--accent);color:#fff;
     font-weight:600;font-size:15px;display:flex;align-items:center;justify-content:center}
  li b{display:block;margin-bottom:4px}
  li p{margin:0;color:var(--dim);font-size:15px}
  .apps{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
  .apps a{flex:1 1 140px;text-align:center;text-decoration:none;
     background:var(--accent);color:#fff;padding:11px 14px;border-radius:10px;font-weight:600}
  code{background:var(--bg);border:1px solid var(--line);border-radius:6px;
     padding:2px 6px;font-size:14px;word-break:break-all}
  .note{background:var(--okbg);color:var(--okink);border-radius:14px;
     padding:16px 18px;margin-top:22px;font-size:15px}
  .note b{display:block;margin-bottom:4px}
  footer{color:var(--dim);font-size:13px;margin-top:26px;text-align:center}
</style>
</head>
<body>
<main>
  <h1>Настройка VPN</h1>
  <p class="lead">Пять минут, один раз. Дальше работает само.</p>

  <ol>
    <li>
      <b>Установите приложение</b>
      <p>Называется sing-box. Других приложений не нужно.</p>
      <div class="apps">
        <a href="https://apps.apple.com/app/sing-box-vt/id6673731168">iPhone и iPad</a>
        <a href="https://play.google.com/store/apps/details?id=io.nekohasekai.sfa">Android</a>
      </div>
    </li>
    <li>
      <b>Скопируйте свою ссылку</b>
      <p>Её прислали вам отдельным сообщением. Выглядит так:
         <code>https://${host}/sub/…</code><br>
         Ссылка личная — не передавайте её другим.</p>
    </li>
    <li>
      <b>Добавьте профиль</b>
      <p>В приложении откройте <b>Profiles</b> → <b>+</b> → тип <b>Remote</b>.
         Вставьте ссылку в поле <b>URL</b>, имя можно любое. Сохраните.</p>
    </li>
    <li>
      <b>Включите</b>
      <p>Вернитесь на главный экран приложения и нажмите большую кнопку включения.
         Система один раз спросит разрешение на VPN — согласитесь.</p>
    </li>
  </ol>

  <div class="note">
    <b>Банки и Госуслуги работают сами</b>
    Российские сайты и приложения идут напрямую, минуя VPN — отключать его
    не нужно. Это настроено за вас.
  </div>

  <div class="note" style="background:transparent;color:var(--dim);border:1px solid var(--line)">
    <b>Если что-то не работает</b>
    Выключите и включите переключатель в приложении. Если не помогло — напишите
    тому, кто дал вам ссылку: возможно, сменился адрес сервера, и профиль нужно
    обновить кнопкой обновления в списке Profiles.
  </div>

  <footer>Личный VPN. Настройки обновляются автоматически.</footer>
</main>
</body>
</html>`;
}
