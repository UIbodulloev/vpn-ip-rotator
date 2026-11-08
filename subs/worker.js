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

// Списки российских сервисов. Раньше их качал сам телефон с raw.githubusercontent
// в виде rule-set — и это была главная причина поломок: в России этот адрес
// заблокирован, поэтому скачивать приходилось через туннель, а туннель на старте
// ещё не поднят. Не скачалось — служба не запускается вовсе. Теперь списки
// подставляются прямо в конфиг, и телефону качать нечего.
//
// Источник ведёт сообщество, руками списки не правим:
//   https://russia.iplist.opencck.org/
const IPLIST = "https://russia.iplist.opencck.org/";

// Целые российские зоны закрываются одним суффиксом каждая — держать их
// в списке доменов незачем.
const RU_TLDS = [".ru", ".su", ".рф", ".xn--p1ai", ".москва", ".tatar", ".дети"];

// На случай, если источник недоступен: крупные российские сервисы вне зоны .ru.
// Деградация честная — домены по-прежнему пойдут мимо VPN, а вот подключения
// прямо по IP-адресу уйдут в туннель.
const FALLBACK_DOMAINS = [
  "2gis.com",
  "adjust.com",
  "auto.yandex",
  "avito.st",
  "bitrix24.com",
  "bitrix24.net",
  "cdek.shopping",
  "clstorage.net",
  "dbankcloud.com",
  "detmir.st",
  "eda.yandex",
  "habr.com",
  "habrastorage.org",
  "metrika.yandex",
  "mradx.net",
  "mvk.com",
  "mycdn.me",
  "naydex.net",
  "ozon.com",
  "ozon.kz",
  "ozon.travel",
  "paywb.com",
  "sbis.link",
  "static-storage.net",
  "tamtam.chat",
  "userapi.com",
  "vk-apps.com",
  "vk-cdn.me",
  "vk-cdn.net",
  "vk-portal.net",
  "vk.cc",
  "vk.com",
  "vk.me",
  "vkcache.com",
  "vkuser.net",
  "vkuseraudio.net",
  "vkuservideo.net",
  "webvisor.com",
  "x5static.net",
  "yads.tech",
  "yandex.by",
  "yandex.cloud",
  "yandex.com",
  "yandex.com.tr",
  "yandex.kz",
  "yandex.net",
  "yandex.st",
  "yandexadexchange.net",
  "yandexcloud.net",
  "yastatic.net",
  "zen.me"
];

// «com.am» и подобное — это не домен, а публичный суффикс: такой фильтр увёл бы
// мимо VPN всю зону целиком.
const PUBLIC_SUFFIX_HEADS = new Set(["com", "net", "org", "co", "gov", "edu"]);

function cleanDomains(text) {
  const out = new Set();
  for (let line of text.split("\n")) {
    line = line.trim().toLowerCase().replace(/^\*\./, "").replace(/^\.+|\.+$/g, "");
    // В источнике попадается мусор вида «yandex.net:443» — такое правило
    // sing-box просто не поймёт.
    if (!line || /[^a-z0-9.\-\u0080-\uffff]/.test(line) || !line.includes(".")) continue;
    const parts = line.split(".");
    if (parts.length === 2 && PUBLIC_SUFFIX_HEADS.has(parts[0])) continue;
    if (RU_TLDS.some((t) => line.endsWith(t))) continue;   // уже покрыто суффиксом зоны
    out.add(line);
  }
  return [...out].sort();
}

function cleanCidr(text) {
  const out = new Set();
  for (const line of text.split("\n")) {
    const v = line.trim();
    if (/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(v)) out.add(v);
  }
  return [...out].sort();
}

/** Списки с кэшированием на сутки. Недоступен источник — отдаём запасной список,
 *  но подписку не ломаем: неработающий VPN хуже неполного списка. */
async function ruLists() {
  const pull = async (query, clean, fallback) => {
    try {
      const answer = await fetch(IPLIST + query, {
        cf: { cacheTtl: 86400, cacheEverything: true },
        signal: AbortSignal.timeout(5000),
      });
      if (!answer.ok) throw new Error(`HTTP ${answer.status}`);
      const list = clean(await answer.text());
      if (list.length < 20) throw new Error("список подозрительно короткий");
      return list;
    } catch {
      return fallback;
    }
  };
  const [domains, cidr] = await Promise.all([
    pull("?format=text&data=domains&wildcard=1", cleanDomains, FALLBACK_DOMAINS),
    pull("?format=text&data=cidr4", cleanCidr, []),
  ]);
  return { domains, cidr };
}

/** Исходящие: Hysteria2 по UDP, VLESS по TCP и автоматический выбор между ними.
 *
 *  У мобильных операторов в России душат длинные TCP-соединения к иностранным
 *  адресам — VLESS подключается и ползёт. UDP при этом проходит. Hysteria2 с
 *  обфускацией salamander выглядит как бесформенный UDP, поэтому идёт на полной
 *  скорости; VLESS остаётся на случай сетей, где режут наоборот — UDP.
 *
 *  Телефон выбирает сам: urltest пробует оба и берёт живой. Hysteria2 стоит
 *  первым, а tolerance большой — чтобы выбор не прыгал туда-сюда на мелкой
 *  разнице задержек.
 */
function proxies(uuid, env) {
  const vless = {
    type: "vless",
    tag: "vless",
    server: env.VPN_HOST,
    server_port: Number(env.VPN_PORT || 443),
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
  };
  const direct = { type: "direct", tag: "direct" };

  if (!env.VPN_HY2_PORT || !env.VPN_HY2_OBFS) {
    return [{ ...vless, tag: "proxy" }, direct];
  }

  const hy2 = {
    type: "hysteria2",
    tag: "hysteria2",
    server: env.VPN_HOST,
    server_port: Number(env.VPN_HY2_PORT),
    password: uuid,
    obfs: { type: "salamander", password: env.VPN_HY2_OBFS },
    tls: { enabled: true, server_name: env.VPN_HOST },
  };
  // Не urltest. Он выбирает по задержке, а задержка у задушенного VLESS как
  // раз хорошая: оператор режет полосу, а не пинг. Телефон честно измерял
  // 48 мс у VLESS против 94 мс у Hysteria2 и уверенно выбирал худший канал.
  // Поэтому выбор жёсткий, с возможностью переключить руками — на случай
  // сети, где режут наоборот, UDP.
  return [
    { type: "selector", tag: "proxy", outbounds: ["hysteria2", "vless"], default: "hysteria2" },
    hy2,
    vless,
    direct,
  ];
}

function singboxConfig(uuid, env, ru) {
  const host = env.VPN_HOST;
  const port = Number(env.VPN_PORT || 443);
  // domain ловит само имя, domain_suffix — поддомены. Поля внутри одного
  // правила объединяются по «или», поэтому всё помещается в одно правило.
  const ruDomain = ru.domains;
  const ruSuffix = RU_TLDS.concat(ru.domains.map((d) => "." + d));

  return {
    log: { level: "warn" },

    dns: {
      // Русские домены резолвим напрямую у российского резолвера: иначе получим
      // ответы для европейской локации и медленный доступ к местным сервисам.
      servers: [
        { type: "udp", tag: "dns-proxy", server: "1.1.1.1", detour: "proxy" },
        // Без detour. В новом формате DNS-сервер набирает соединение сам, как
        // outbound, и detour на пустой direct ядро считает бессмыслицей —
        // отказывается стартовать: «start dns/udp[dns-direct]». Поведение по
        // умолчанию и так прямое, поле было лишним.
        { type: "udp", tag: "dns-direct", server: "77.88.8.8" },
      ],
      rules: [{ domain: ruDomain, domain_suffix: ruSuffix, action: "route", server: "dns-direct" }],
      final: "dns-proxy",
      strategy: "ipv4_only",
    },

    inbounds: [
      {
        type: "tun",
        tag: "tun-in",
        address: ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
        // 1400, а не значение по умолчанию. Телефон объявляет приложениям тот
        // размер пакета, который видит на tun; при девяти тысячах YouTube
        // отправляет QUIC-датаграммы, которые в реальный канал не влезают,
        // теряются и пересылаются заново. Внешне это «скорость высокая, а
        // Shorts подтормаживают».
        mtu: 1400,
        auto_route: true,
        strict_route: true,
      },
    ],

    outbounds: proxies(uuid, env),

    route: {
      rules: [
        { action: "sniff" },
        { protocol: "dns", action: "hijack-dns" },
        // Локальная сеть — мимо туннеля, иначе отвалится доступ к роутеру и принтеру.
        { ip_is_private: true, action: "route", outbound: "direct" },
        // Банки, Госуслуги и прочее российское — напрямую, без VPN.
        {
          domain: ruDomain,
          domain_suffix: ruSuffix,
          ip_cidr: ru.cidr,
          action: "route",
          outbound: "direct",
        },
      ],
      final: "proxy",
      auto_detect_interface: true,
      // Адрес сервера у нас домен, а не IP, и его надо разрешить ДО туннеля.
      // С sing-box 1.14 это обязательное поле, если DNS-серверов больше одного:
      // без него профиль не запускается вовсе.
      default_domain_resolver: "dns-direct",
    },

    experimental: {
      cache_file: { enabled: true },
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
      const body = JSON.stringify(singboxConfig(uuid.toLowerCase(), env, await ruLists()), null, 2);
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
      <p>Называется <b>sing-box</b>. Других приложений не нужно.</p>
      <div class="apps">
        <a href="https://play.google.com/store/apps/details?id=io.nekohasekai.sfa">Android</a>
        <a href="https://apps.apple.com/app/sing-box-vt/id6673731168">iPhone и iPad</a>
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
      <p>Скопируйте ссылку, откройте приложение и нажмите <b>+</b> —
         оно само предложит добавить её из буфера обмена.</p>
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
    <b>Банковское приложение капризничает?</b>
    На Android можно убрать его из VPN целиком: в настройках приложения
    найдите <b>Per-app proxy</b> и снимите галочки с банков и Госуслуг. Такие приложения иногда ходят к своим серверам
    напрямую по адресу, минуя имена сайтов, и тогда список российских
    доменов им не помогает. На iPhone такой настройки нет — там, если
    приложение не пускает, выключите VPN на минуту.
  </div>

  <div class="note" style="background:transparent;color:var(--dim);border:1px solid var(--line)">
    <b>Если вам дали ссылку на <code>vless://</code></b>
    Это упрощённый вариант: он тоже работает, но через VPN идёт <i>весь</i>
    трафик, включая российские сайты. Зато её понимает любое приложение —
    и sing-box, и Hiddify, и v2rayNG. Если хотите, чтобы банки шли напрямую,
    попросите у того, кто дал ссылку, подписку вместо неё.
  </div>

  <div class="note" style="background:transparent;color:var(--dim);border:1px solid var(--line)">
    <b>Если приложение не подключается</b>
    Сначала попробуйте <b>Hiddify</b> — это второе приложение, которое понимает
    такую же ссылку. Одно из двух обычно соединяется: они используют разные
    версии одного и того же движка. Если не помогло ни одно, напишите тому, кто
    дал вам ссылку, и покажите текст ошибки — это чинится на сервере.
  </div>

  <div class="note" style="background:transparent;color:var(--dim);border:1px solid var(--line)">
    <b>Если что-то не работает</b>
    Выключите и включите переключатель в приложении. Если не помогло — напишите
    тому, кто дал вам ссылку: возможно, сменился адрес сервера, и профиль нужно
    обновить кнопкой обновления в списке профилей.
  </div>

  <footer>Личный VPN. Настройки обновляются автоматически.</footer>
</main>
</body>
</html>`;
}
