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
  // Объявленная полоса включает на сервере Brutal: он держит скорость, не
  // отступая при потерях. Выключено по умолчанию — цифра одна на все сети,
  // а у телефона их две, и правильного значения для обеих не существует.
  // Перескок портов: клиент шлёт по всему диапазону, сервер сводит их на один.
  if (env.VPN_HY2_PORTS) {
    hy2.server_ports = [env.VPN_HY2_PORTS];
  }
  if (env.VPN_HY2_UP && env.VPN_HY2_DOWN) {
    hy2.up_mbps = Number(env.VPN_HY2_UP);
    hy2.down_mbps = Number(env.VPN_HY2_DOWN);
  }
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
        // Fake-IP: на запрос имени телефон получает ответ мгновенно, из
        // служебного диапазона, и сразу открывает соединение. Настоящее имя
        // достаётся из самого соединения и по нему принимается решение. Иначе
        // перед каждым новым хостом уходит лишний обход до сервера и обратно —
        // на мобильной сети это те самые 90 мс паузы перед картинкой.
        { type: "fakeip", tag: "dns-fake", inet4_range: "198.18.0.0/15", inet6_range: "fc00::/18" },
        // Без detour. В новом формате DNS-сервер набирает соединение сам, как
        // outbound, и detour на пустой direct ядро считает бессмыслицей —
        // отказывается стартовать: «start dns/udp[dns-direct]». Поведение по
        // умолчанию и так прямое, поле было лишним.
        { type: "udp", tag: "dns-direct", server: "77.88.8.8" },
      ],
      rules: [
        // Российское резолвим по-настоящему: его адреса нужны правилу по IP.
        { domain: ruDomain, domain_suffix: ruSuffix, action: "route", server: "dns-direct" },
        { query_type: ["A", "AAAA"], action: "route", server: "dns-fake" },
      ],
      final: "dns-proxy",
      strategy: "ipv4_only",
    },

    inbounds: [
      {
        type: "tun",
        tag: "tun-in",
        address: ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
        // 1280 — минимум, который обязана пропускать любая IP-сеть, и то же
        // значение, что по умолчанию берёт Amnezia. Почему не больше: дома
        // телефон может оказаться за роутером, который сам сидит в туннеле.
        // У такого туннеля MTU 1420, и пакет на 1400 плюс обёртка Hysteria2
        // (около 70 байт) в него уже не влезает — молча теряется. На мобильной
        // сети это незаметно: там один слой и запас до 1500. Отсюда и
        // «на мобильной работает, дома нет».
        mtu: 1280,
        auto_route: true,
        strict_route: true,
      },
    ],

    outbounds: proxies(uuid, env),

    route: {
      rules: [
        { action: "sniff" },
        { protocol: "dns", action: "hijack-dns" },
        // QUIC в отказ. YouTube и Google ходят по HTTP/3 поверх UDP, и внутри
        // туннеля это ведёт себя заметно хуже, чем обычный HTTPS: своя
        // подстройка под потери поверх чужой, свой подбор размера пакета
        // поверх чужого. Получив отказ, приложение само переходит на TCP —
        // ровно то, с чем прокси справляется хорошо. Это и есть разница между
        // «скорость высокая» и «превью не грузятся».
        { protocol: "quic", action: "reject" },
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
      // store_fakeip: иначе после перезапуска соответствия имя-адрес теряются
      // и первые обращения к уже открытым приложениям срываются.
      cache_file: { enabled: true, store_fakeip: true },
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
 * ни скриптов, ни картинок по сети — чтобы открывалась и там, где половина
 * интернета недоступна. Рисунки экранов — inline SVG: это схемы, а не снимки,
 * зато они весят килобайты и читаются в тёмной теме.
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
    --soft:#eef2f7; --warn:#fdf3e3; --warnink:#7a5218;
  }
  @media (prefers-color-scheme:dark){
    :root{ --bg:#14171c; --card:#1c2026; --ink:#e8eaed; --dim:#9aa2ae;
           --line:#2b313a; --accent:#6aa9f5; --okbg:#182a1d; --okink:#8fd3a0;
           --soft:#23282f; --warn:#2a2316; --warnink:#e0c38a; }
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);
       font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
       padding:24px 16px 56px}
  main{max-width:620px;margin:0 auto}
  h1{font-size:26px;line-height:1.25;margin:0 0 6px}
  h2{font-size:20px;line-height:1.3;margin:36px 0 4px}
  .lead{color:var(--dim);margin:0 0 24px}
  .sub{color:var(--dim);margin:0 0 16px;font-size:15px}

  /* Что прислали */
  .got{background:var(--card);border:1px solid var(--line);border-radius:14px;
       padding:16px 18px;margin-bottom:10px;display:flex;gap:14px;align-items:flex-start}
  .got .ico{flex:0 0 38px}
  .got b{display:block;margin-bottom:2px}
  .got p{margin:0;color:var(--dim);font-size:15px}

  /* Шаги */
  ol{list-style:none;counter-reset:s;padding:0;margin:0}
  li{counter-increment:s;background:var(--card);border:1px solid var(--line);
     border-radius:14px;padding:18px 18px 18px 60px;margin-bottom:12px;position:relative}
  li::before{content:counter(s);position:absolute;left:18px;top:17px;
     width:28px;height:28px;border-radius:50%;background:var(--accent);color:#fff;
     font-weight:600;font-size:15px;display:flex;align-items:center;justify-content:center}
  li b{display:block;margin-bottom:4px}
  li p{margin:0;color:var(--dim);font-size:15px}
  li p+p{margin-top:8px}

  figure{margin:14px 0 0;text-align:center}
  figure svg{width:100%;max-width:270px;height:auto;
     border-radius:12px;background:var(--soft)}
  figcaption{color:var(--dim);font-size:13px;margin-top:6px}

  .apps{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
  .apps a{flex:1 1 130px;text-align:center;text-decoration:none;
     background:var(--accent);color:#fff;padding:11px 14px;border-radius:10px;
     font-weight:600;font-size:15px}
  code{background:var(--bg);border:1px solid var(--line);border-radius:6px;
     padding:2px 6px;font-size:14px;word-break:break-all}
  .note{background:var(--okbg);color:var(--okink);border-radius:14px;
     padding:16px 18px;margin-top:16px;font-size:15px}
  .note b{display:block;margin-bottom:4px}
  .plain{background:transparent;color:var(--dim);border:1px solid var(--line)}
  .warn{background:var(--warn);color:var(--warnink)}
  details{background:var(--card);border:1px solid var(--line);border-radius:14px;
     padding:14px 18px;margin-top:10px}
  details summary{cursor:pointer;font-weight:600}
  details p{color:var(--dim);font-size:15px;margin:10px 0 0}
  footer{color:var(--dim);font-size:13px;margin-top:34px;text-align:center}
</style>
</head>
<body>
<main>
  <h1>Как включить VPN</h1>
  <p class="lead">Пять минут, один раз. Дальше работает само.</p>

  <h2>Что вам прислали</h2>
  <p class="sub">В сообщении две вещи. Начните со <b>ссылки</b> — файл нужен
     только как запасной вариант.</p>

  <div class="got">
    <svg class="ico" viewBox="0 0 38 38" aria-hidden="true">
      <rect x="1" y="9" width="36" height="20" rx="10" fill="none"
            stroke="var(--accent)" stroke-width="2"/>
      <path d="M12 19h14" stroke="var(--accent)" stroke-width="2" stroke-linecap="round"/>
      <circle cx="12" cy="19" r="3.2" fill="var(--accent)"/>
      <circle cx="26" cy="19" r="3.2" fill="var(--accent)"/>
    </svg>
    <div>
      <b>Ссылка вида https://${host}/sub/…</b>
      <p>Главное. Телефон сам скачивает по ней настройки и сам их обновляет.
         Если сервер переедет — у вас ничего не сломается.</p>
    </div>
  </div>

  <div class="got">
    <svg class="ico" viewBox="0 0 38 38" aria-hidden="true">
      <path d="M9 3h13l8 8v24H9z" fill="none" stroke="var(--dim)" stroke-width="2"/>
      <path d="M22 3v8h8" fill="none" stroke="var(--dim)" stroke-width="2"/>
      <path d="M14 20h10M14 26h10" stroke="var(--dim)" stroke-width="2" stroke-linecap="round"/>
    </svg>
    <div>
      <b>Файл с названием вида имя.conf</b>
      <p>Запасной канал на случай, если первый способ не пойдёт, и
         единственный способ для роутера. Другое приложение, другая технология.</p>
    </div>
  </div>

  <h2>Способ 1 · Телефон</h2>
  <p class="sub">Начните с него.</p>

  <ol>
    <li>
      <b>Установите приложение sing-box</b>
      <p>Других приложений не нужно. В магазине оно так и называется —
         <b>sing-box</b>, значок чёрно-белый.</p>
      <div class="apps">
        <a href="https://play.google.com/store/apps/details?id=io.nekohasekai.sfa">Android</a>
        <a href="https://apps.apple.com/app/sing-box-vt/id6673731168">iPhone и iPad</a>
      </div>
    </li>

    <li>
      <b>Скопируйте присланную ссылку</b>
      <p>Задержите палец на ссылке в сообщении и выберите <b>Копировать</b>.
         Открывать её в браузере не нужно — браузер покажет непонятный текст,
         и это нормально.</p>
      <figure>
        <svg viewBox="0 0 270 150" role="img" aria-label="Сообщение со ссылкой и меню копирования">
          <rect x="14" y="16" width="200" height="46" rx="12" fill="var(--card)"
                stroke="var(--line)"/>
          <text x="28" y="36" font-size="11" fill="var(--dim)">Ваш личный VPN</text>
          <text x="28" y="52" font-size="11" fill="var(--accent)">https://…/sub/a1b2…</text>
          <rect x="60" y="74" width="150" height="60" rx="12" fill="var(--card)"
                stroke="var(--accent)" stroke-width="2"/>
          <rect x="68" y="82" width="134" height="24" rx="7" fill="var(--accent)" opacity="0.14"/>
          <text x="80" y="98" font-size="12" font-weight="600" fill="var(--ink)">Копировать</text>
          <text x="80" y="124" font-size="12" fill="var(--dim)">Открыть</text>
        </svg>
        <figcaption>Схема: длинное нажатие на ссылку</figcaption>
      </figure>
    </li>

    <li>
      <b>Добавьте профиль в приложение</b>
      <p>Откройте sing-box, внизу выберите <b>Профили</b> и нажмите <b>+</b>
         в правом верхнем углу. В открывшемся окне выберите
         <b>Импорт из буфера обмена</b> — приложение подставит вашу ссылку само.</p>
      <p>Если такого пункта нет, выберите <b>Удалённый профиль</b> (Remote) и
         вставьте ссылку в поле адреса, имя — любое.</p>
      <figure>
        <svg viewBox="0 0 270 190" role="img" aria-label="Экран профилей с кнопкой плюс">
          <rect x="35" y="8" width="200" height="174" rx="16" fill="var(--card)"
                stroke="var(--line)"/>
          <text x="52" y="34" font-size="13" font-weight="600" fill="var(--ink)">Профили</text>
          <circle cx="212" cy="29" r="15" fill="var(--accent)"/>
          <path d="M212 22v14M205 29h14" stroke="#fff" stroke-width="2.4" stroke-linecap="round"/>
          <circle cx="212" cy="29" r="22" fill="none" stroke="var(--accent)"
                  stroke-width="1.5" stroke-dasharray="4 4"/>
          <rect x="52" y="54" width="166" height="34" rx="9" fill="var(--soft)"/>
          <text x="64" y="75" font-size="11" fill="var(--dim)">пока ни одного</text>
          <rect x="52" y="104" width="166" height="62" rx="11" fill="var(--bg)"
                stroke="var(--accent)" stroke-width="1.5"/>
          <text x="64" y="126" font-size="11" font-weight="600" fill="var(--ink)">Импорт из буфера</text>
          <text x="64" y="146" font-size="11" fill="var(--dim)">Удалённый профиль</text>
        </svg>
        <figcaption>Схема: кнопка + на экране «Профили»</figcaption>
      </figure>
    </li>

    <li>
      <b>Включите</b>
      <p>Вернитесь на первый экран и нажмите большую круглую кнопку.
         Телефон один раз спросит разрешение на VPN — согласитесь.
         Сверху появится значок ключика или VPN: он и значит, что всё работает.</p>
      <figure>
        <svg viewBox="0 0 270 190" role="img" aria-label="Главный экран с кнопкой включения">
          <rect x="35" y="8" width="200" height="174" rx="16" fill="var(--card)"
                stroke="var(--line)"/>
          <circle cx="135" cy="86" r="42" fill="var(--accent)" opacity="0.14"/>
          <circle cx="135" cy="86" r="42" fill="none" stroke="var(--accent)" stroke-width="3"/>
          <path d="M135 66v26" stroke="var(--accent)" stroke-width="4" stroke-linecap="round"/>
          <path d="M118 72a23 23 0 1 0 34 0" fill="none" stroke="var(--accent)"
                stroke-width="4" stroke-linecap="round"/>
          <text x="135" y="152" font-size="12" font-weight="600" text-anchor="middle"
                fill="var(--okink)">Подключено</text>
        </svg>
        <figcaption>Схема: кнопка включения</figcaption>
      </figure>
    </li>

    <li>
      <b>Проверьте</b>
      <p>Откройте YouTube. Если видео играет — готово, больше ничего делать не нужно.
         Приложение можно закрыть, VPN останется включённым.</p>
    </li>
  </ol>

  <div class="note">
    <b>Банки и Госуслуги работают сами</b>
    Российские сайты и приложения идут напрямую, минуя VPN. Выключать его
    не нужно — это уже настроено за вас.
  </div>

  <h2>Способ 2 · Файл AmneziaWG</h2>
  <p class="sub">Нужен в двух случаях: первый способ не заработал или вы
     настраиваете роутер.</p>

  <ol>
    <li>
      <b>Установите приложение AmneziaWG</b>
      <p>Именно <b>AmneziaWG</b>, а не <b>Amnezia VPN</b> — это два разных
         приложения одного автора, и второе вам не подойдёт.</p>
      <div class="apps">
        <a href="https://play.google.com/store/apps/details?id=org.amnezia.awg">Android</a>
        <a href="https://apps.apple.com/app/amneziawg/id6478942365">iPhone и iPad</a>
      </div>
    </li>
    <li>
      <b>Откройте присланный файл</b>
      <p>Нажмите на файл в сообщении и выберите <b>Открыть в AmneziaWG</b>.
         Приложение само создаст подключение.</p>
      <p>Если выбора не предложили: сохраните файл, откройте AmneziaWG,
         нажмите <b>+</b> и выберите <b>Импорт из файла</b>.</p>
      <figure>
        <svg viewBox="0 0 270 150" role="img" aria-label="Файл открывается в приложении">
          <rect x="16" y="46" width="60" height="58" rx="9" fill="var(--card)"
                stroke="var(--line)"/>
          <path d="M34 62h18M34 74h24M34 86h24" stroke="var(--dim)" stroke-width="2"
                stroke-linecap="round"/>
          <text x="46" y="118" font-size="10" text-anchor="middle" fill="var(--dim)">имя.conf</text>
          <path d="M92 75h58" stroke="var(--accent)" stroke-width="2.5" stroke-linecap="round"/>
          <path d="M142 68l9 7-9 7" fill="none" stroke="var(--accent)" stroke-width="2.5"
                stroke-linecap="round" stroke-linejoin="round"/>
          <rect x="166" y="34" width="86" height="82" rx="14" fill="var(--card)"
                stroke="var(--accent)" stroke-width="2"/>
          <text x="209" y="62" font-size="11" font-weight="600" text-anchor="middle"
                fill="var(--ink)">AmneziaWG</text>
          <rect x="182" y="74" width="54" height="22" rx="7" fill="var(--accent)"/>
          <text x="209" y="89" font-size="10" font-weight="600" text-anchor="middle"
                fill="#fff">Добавить</text>
        </svg>
        <figcaption>Схема: открыть файл в AmneziaWG</figcaption>
      </figure>
    </li>
    <li>
      <b>Включите переключатель</b>
      <p>В списке появится ваше подключение — сдвиньте переключатель справа.
         Телефон спросит разрешение на VPN один раз.</p>
    </li>
  </ol>

  <div class="note plain">
    <b>Чем этот способ отличается</b>
    Файл не обновляется сам. Если сервер переедет, подключение перестанет
    работать и файл придётся попросить заново. У ссылки из первого способа
    такой беды нет. Поэтому файл — запасной, а не основной.
  </div>

  <h2>Если что-то не так</h2>

  <details>
    <summary>Ссылка не открывается, профиль не скачивается</summary>
    <p>Так бывает у некоторых мобильных операторов. Попробуйте с Wi-Fi: профиль
       скачается один раз и дальше будет работать в любой сети. Если Wi-Fi нет —
       напишите тому, кто дал вам ссылку, и попросите <b>файл профиля</b>:
       он добавляется без интернета.</p>
  </details>

  <details>
    <summary>Приложение подключилось, но сайты не открываются</summary>
    <p>Выключите и включите кнопку в приложении. Не помогло — перезагрузите
       телефон. Если и это не помогло, напишите тому, кто дал ссылку:
       возможно, нужно обновить профиль кнопкой обновления в списке профилей.</p>
  </details>

  <details>
    <summary>Банковское приложение капризничает</summary>
    <p>На Android его можно убрать из VPN целиком: в настройках sing-box
       найдите <b>Per-app proxy</b> и снимите галочки с банков и Госуслуг.
       Такие приложения иногда ходят к своим серверам напрямую по адресу,
       минуя имена сайтов, и тогда список российских сайтов им не помогает.
       На iPhone такой настройки нет — выключите VPN на минуту.</p>
  </details>

  <details>
    <summary>sing-box не запускается или пишет ошибку</summary>
    <p>Сначала обновите приложение в магазине: старые версии не понимают
       новые настройки, и это самая частая причина. Если не помогло,
       установите <b>Hiddify</b> — оно понимает ту же ссылку и использует
       другую версию того же движка. Одно из двух обычно соединяется.
       Текст ошибки покажите тому, кто дал вам ссылку: это чинится на сервере.</p>
  </details>

  <details>
    <summary>Хочу поставить на второе устройство</summary>
    <p>Попросите второй ключ. Ссылка и файл рассчитаны на одно устройство:
       если включить их на двух, оба будут работать с перебоями — так устроена
       защита от передачи ключей посторонним.</p>
  </details>

  <details>
    <summary>Мне дали только ссылку vless://</summary>
    <p>Это упрощённый вариант: он тоже работает, но через VPN идёт <i>весь</i>
       трафик, включая российские сайты и банки. Зато её понимает любое
       приложение — sing-box, Hiddify, v2rayNG, v2RayTun. Хотите, чтобы банки
       шли напрямую, — попросите ссылку на подписку вместо неё.</p>
  </details>

  <div class="note warn">
    <b>Ключи личные</b>
    Не публикуйте и не пересылайте их. По ключу видно, кому он выдан,
    а если им пользуется кто-то ещё, у вас начнутся обрывы.
  </div>

  <footer>Личный VPN. Настройки обновляются автоматически.</footer>
</main>
</body>
</html>`;
}
