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

// Android-приложения, которые идут мимо VPN целиком: см. exclude_package в tun.
const BYPASS_APPS = [
  // банки
  "ru.sberbankmobile", "ru.sberbank.sberbankid", "com.idamob.tinkoff.android",
  "ru.vtb24.mobilebanking.android", "ru.alfabank.mobile.android", "ru.raiffeisennews",
  "ru.gazprombank.android.mobilebank.app", "ru.psbank.online", "ru.rosbank.android",
  "ru.mkb.mobile", "ru.sovcombank.halvacard", "com.openbank", "ru.pochta.bank",
  "com.yandex.bank", "ru.ozon.fintech.finance", "ru.nspk.mirpay", "ru.otpbank.mobile",
  "ru.yoo.money", "ru.tinkoff.investing",
  // государство
  "ru.rostel", "ru.gosuslugi.goskey", "ru.nalog.www", "ru.fns.lkfl", "ru.mos.app",
  // маркетплейсы и сервисы
  "ru.ozon.app.android", "com.wildberries.ru", "ru.yandex.taxi", "ru.yandex.yandexmaps",
  "ru.yandex.yandexnavi", "ru.yandex.market", "com.avito.android", "ru.oneme.app",
  // операторы связи
  "ru.mts.mymts", "ru.megafon.mlk", "ru.beeline.services", "ru.tele2.mytele2",
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
  // Каждый список возвращается вместе с тем, откуда он взялся: «live» —
  // свежий из источника, «fallback» — запасной. Это видно в /health и в
  // заголовке x-lists, и сторож на сервере сообщает о деградации в бот:
  // раньше переход на запасной список случался молча.
  const pull = async (url, clean, fallback, min) => {
    try {
      const answer = await fetch(url, {
        cf: { cacheTtl: 86400, cacheEverything: true },
        signal: AbortSignal.timeout(5000),
      });
      if (!answer.ok) throw new Error(`HTTP ${answer.status}`);
      const list = clean(await answer.text());
      if (list.length < min) throw new Error("список подозрительно короткий");
      return { list, source: "live" };
    } catch (err) {
      return { list: fallback, source: "fallback", error: String(err && err.message || err) };
    }
  };
  const [domains, cidr, ...blocked] = await Promise.all([
    pull(IPLIST + "?format=text&data=domains&wildcard=1", cleanDomains, FALLBACK_DOMAINS, 20),
    pull(IPLIST + "?format=text&data=cidr4", cleanCidr, [], 20),
    ...BLOCKED_SOURCES.map((url) => pull(url, cleanBlocked, [], 5)),
  ]);
  return {
    domains: domains.list,
    cidr: cidr.list,
    blocked: blockedInRu(blocked.flatMap((b) => b.list), domains.list),
    status: {
      domains: { source: domains.source, count: domains.list.length, error: domains.error },
      cidr: { source: cidr.source, count: cidr.list.length, error: cidr.error },
      blocked: blocked.map((b, i) => ({ url: BLOCKED_SOURCES[i], source: b.source,
                                        count: b.list.length, error: b.error })),
    },
  };
}

// Заблокированное в России. Без этого российский сайт, который сам заблокирован
// РКН (новостные, торренты, аниме — в .ru/.su таких десятки), попадал под
// правило «российское напрямую» и просто не открывался. Берём два курируемых
// списка популярных заблокированных доменов (не весь реестр на 1,8 млн строк)
// и оставляем из них только те, что иначе ушли бы напрямую: остальное и так
// идёт через VPN по умолчанию.
// Качает их сам воркер на Cloudflare, а не телефон: в конфиг списки попадают
// уже готовыми, как и российские (тест test_подписка_ничего_не_качает_на_старте).
const BLOCKED_SOURCES = [
  "https://cdn.jsdelivr.net/gh/itdoginfo/allow-domains@main/Russia/inside-raw.lst",
  "https://community.antifilter.download/list/domains.lst",
];

function cleanBlocked(text) {
  const out = new Set();
  for (let line of text.split("\n")) {
    line = line.trim().toLowerCase().replace(/^\*\./, "").replace(/^\.+|\.+$/g, "");
    if (!line || /[^a-z0-9.\-]/.test(line) || !line.includes(".")) continue;
    out.add(line);
  }
  return [...out];
}

/** Из заблокированных — только то, что попало бы под «российское напрямую». */
function blockedInRu(blocked, ruDomains) {
  const ru = new Set(ruDomains);
  const zones = RU_TLDS.concat([".xn--p1ai"]);
  const out = new Set();
  for (const d of blocked) {
    let direct = zones.some((z) => d.endsWith(z));
    for (let s = d; !direct && s.includes("."); s = s.slice(s.indexOf(".") + 1)) {
      if (ru.has(s)) direct = true;
    }
    if (direct) out.add(d);
  }
  return [...out].sort();
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
  // Основной Hysteria2, запасной VLESS — и переключение само, если основной умер.
  //
  // Голый urltest не годится: он выбирает по задержке, а задержка у задушенного
  // VLESS как раз хорошая — оператор режет полосу, а не пинг (телефон мерил 48 мс
  // у VLESS против 94 мс у Hysteria2 и уверенно выбирал худший канал). Проверка
  // в sing-box — один крошечный HEAD-запрос, торможение после первых килобайт
  // она не видит в принципе.
  //
  // Но у urltest есть свойство, которое делает из него «основной + запасной»:
  // кандидаты перебираются по порядку, и следующий отбирает выбор, только если
  // быстрее предыдущего больше чем на tolerance (protocol/group/urltest.go,
  // Select). Hysteria2 стоит первым, tolerance — секунда: пока он отвечает,
  // выбран он, каким бы быстрым ни казался VLESS. Перестал отвечать (оператор
  // закрыл UDP) — его история стирается, и выбор уходит на VLESS. Вернётся
  // Hysteria2 — телефон останется на VLESS до перезапуска VPN или до отказа
  // VLESS: прыгать туда-сюда на живом канале хуже.
  //
  // Руками по-прежнему можно выбрать любой канал в «Группах» → proxy.
  return [
    { type: "selector", tag: "proxy", outbounds: ["auto", "hysteria2", "vless"], default: "auto" },
    {
      type: "urltest",
      tag: "auto",
      outbounds: ["hysteria2", "vless"],
      url: "https://www.gstatic.com/generate_204",
      interval: "1m",
      tolerance: 1000,
      // Сменился канал — рвём старые соединения, чтобы приложения сразу
      // переподключились по живому, а не висели на умершем.
      interrupt_exist_connections: true,
    },
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
  // Российское, но заблокированное в России: эти правила стоят раньше
  // «российского напрямую» и отправляют такие сайты через VPN. Пустой список —
  // пустые правила sing-box считает ошибкой, поэтому тогда их нет вовсе.
  const blocked = ru.blocked || [];
  const blockedMatch = { domain: blocked, domain_suffix: blocked.map((d) => "." + d) };
  const blockedDns = blocked.length ? [
    // Имя — через fake-IP, как всё заграничное: настоящий адрес найдёт сервер.
    // Российский DNS для таких сайтов часто отдаёт заглушку провайдера.
    { ...blockedMatch, query_type: ["A", "AAAA"], action: "route", server: "dns-fake" },
    { ...blockedMatch, action: "route", server: "dns-proxy" },
  ] : [];
  const blockedRoute = blocked.length ? [{ ...blockedMatch, action: "route", outbound: "proxy" }] : [];

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
        ...blockedDns,
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
        // MTU интерфейса tun — это размер пакета между приложением и самим
        // sing-box на телефоне, а не размер пакета в сети. TCP sing-box
        // завершает у себя и к серверу открывает обычное соединение, которое
        // само узнаёт MTU пути. UDP Hysteria2 режет на датаграммы сама, VLESS
        // везёт внутри TCP. Поэтому опасение «пакет не влезет в туннель
        // роутера» к tun не относится, а маленький MTU только множит пакеты:
        // при 1280 телефон на тех же 50 Мбит/с перекладывает их в семь раз
        // больше, чем при 9000, и упирается в процессор. 9000 — значение
        // по умолчанию в самом sing-box.
        mtu: 9000,
        auto_route: true,
        strict_route: true,
        // Банки, Госуслуги, маркетплейсы и операторы — мимо VPN целиком
        // (только Android). Такие приложения ходят к серверам по IP, проверяют
        // страну адреса и замечают VPN по самому интерфейсу; список доменов
        // им не помогает, а исключение помогает всегда. Человеку ничего не
        // нужно настраивать руками. Отсутствующие на телефоне пакеты sing-box
        // просто пропускает.
        exclude_package: BYPASS_APPS,
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
        // ровно то, с чем прокси справляется хорошо.
        //
        // no_drop обязателен. Без него sing-box после 50 отказов за 30 секунд
        // перестаёт отвечать и молча роняет пакеты, а YouTube и Instagram
        // набирают полсотни попыток QUIC за пару секунд. Дальше каждое новое
        // соединение ждёт таймаута, прежде чем уйти на TCP: превью грузятся
        // рывками, ролики переключаются с паузой. С Amnezia такого нет — там
        // QUIC просто идёт. С no_drop отказ всегда мгновенный (ICMP), и
        // приложение переходит на TCP сразу.
        { protocol: "quic", action: "reject", no_drop: true },
        // Локальная сеть — мимо туннеля, иначе отвалится доступ к роутеру и принтеру.
        { ip_is_private: true, action: "route", outbound: "direct" },
        // Заблокированное в России — через VPN, даже если оно в .ru.
        ...blockedRoute,
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

    // Состояние списков: откуда взялись и сколько их. Его раз в несколько
    // часов проверяет сторож на VPN-сервере (panel/watchdog.py) и сообщает в
    // бот, если генератор перешёл на запасной список. Ключей здесь нет.
    if (parts.length === 1 && parts[0] === "health") {
      const ru = await ruLists();
      const body = JSON.stringify({ ok: ru.status.domains.source === "live" && ru.status.cidr.source === "live",
                                    blocked_ru: ru.blocked.length, ...ru.status }, null, 2);
      return new Response(body, {
        headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
      });
    }

    const [kind, uuid] = parts;
    if (!UUID_RE.test(uuid || "")) {
      return new Response("not found\n", { status: 404 });
    }

    if (kind === "sub") {
      const ru = await ruLists();
      const body = JSON.stringify(singboxConfig(uuid.toLowerCase(), env, ru), null, 2);
      const s = ru.status;
      return new Response(body, {
        headers: {
          "content-type": "application/json; charset=utf-8",
          "cache-control": "no-store",
          // Имя профиля в приложении и интервал обновления подписки.
          "profile-title": "VPN",
          "profile-update-interval": "24",
          "x-lists": `domains=${s.domains.source}:${s.domains.count} cidr=${s.cidr.source}:${s.cidr.count} blocked_ru=${ru.blocked.length}`,
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
  /* Заголовок карточки — только первый <b>, а не любое выделение в тексте:
     иначе каждое жирное слово в абзаце уезжало на отдельную строку. */
  .got div > b:first-child{display:block;margin-bottom:2px}
  .got p{margin:0;color:var(--dim);font-size:15px}

  /* Шаги */
  ol{list-style:none;counter-reset:s;padding:0;margin:0}
  li{counter-increment:s;background:var(--card);border:1px solid var(--line);
     border-radius:14px;padding:18px 18px 18px 60px;margin-bottom:12px;position:relative}
  li::before{content:counter(s);position:absolute;left:18px;top:17px;
     width:28px;height:28px;border-radius:50%;background:var(--accent);color:#fff;
     font-weight:600;font-size:15px;display:flex;align-items:center;justify-content:center}
  li > b{display:block;margin-bottom:4px}
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
  .note > b{display:block;margin-bottom:4px}
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
  <p class="lead">Три минуты, один раз. Дальше всё работает и обновляется само.</p>

  <div class="note">
    <b>Что вы получите</b>
    YouTube, Instagram, ChatGPT и всё заблокированное открываются быстро.
    Банки, Госуслуги, маркетплейсы и другие российские сервисы работают
    напрямую, как без VPN — выключать его не нужно.
  </div>

  <h2>Что вам прислали</h2>
  <p class="sub">Главное — <b>ссылка</b>. Файл прилагают не всем: он запасной.</p>

  <div class="got">
    <svg class="ico" viewBox="0 0 38 38" aria-hidden="true">
      <rect x="1" y="9" width="36" height="20" rx="10" fill="none"
            stroke="var(--accent)" stroke-width="2"/>
      <path d="M12 19h14" stroke="var(--accent)" stroke-width="2" stroke-linecap="round"/>
      <circle cx="12" cy="19" r="3.2" fill="var(--accent)"/>
      <circle cx="26" cy="19" r="3.2" fill="var(--accent)"/>
    </svg>
    <div>
      <b>Ссылка вида https://…/sub/…</b>
      <p>Это ваш личный ключ. Приложение скачивает по нему настройки и само
         их обновляет: если сервер переедет или что-то улучшат — у вас всё
         продолжит работать без единого действия.</p>
    </div>
  </div>

  <div class="got">
    <svg class="ico" viewBox="0 0 38 38" aria-hidden="true">
      <path d="M9 3h13l8 8v24H9z" fill="none" stroke="var(--dim)" stroke-width="2"/>
      <path d="M22 3v8h8" fill="none" stroke="var(--dim)" stroke-width="2"/>
      <path d="M14 20h10M14 26h10" stroke="var(--dim)" stroke-width="2" stroke-linecap="round"/>
    </svg>
    <div>
      <b>Файл имя.conf — если прислали</b>
      <p>Запасной канал на другой технологии (AmneziaWG) и единственный
         способ для роутера. Нет файла — он вам не нужен.</p>
    </div>
  </div>

  <h2>Способ 1 · Телефон или планшет</h2>
  <p class="sub">Подходит и для Android, и для iPhone. Начните с него.</p>

  <ol>
    <li>
      <b>Установите приложение sing-box</b>
      <p>Оно бесплатное, значок чёрно-белый. На iPhone в App Store оно
         называется <b>sing-box VT</b>.</p>
      <div class="apps">
        <a href="https://play.google.com/store/apps/details?id=io.nekohasekai.sfa">Android</a>
        <a href="https://apps.apple.com/app/sing-box-vt/id6673731168">iPhone и iPad</a>
      </div>
    </li>

    <li>
      <b>Скопируйте свою ссылку</b>
      <p>Задержите палец на ссылке в сообщении и выберите <b>Копировать</b>.
         Открывать её в браузере не нужно.</p>
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
        <figcaption>Длинное нажатие на ссылку → Копировать</figcaption>
      </figure>
    </li>

    <li>
      <b>Добавьте профиль</b>
      <p>Откройте sing-box. На главном экране в блоке <b>Профили</b> нажмите
         <b>+</b> и выберите <b>Создать вручную</b>.</p>
      <p>Имя — любое, например <b>VPN</b>. Тип — <b>Удалённый</b>.
         В поле <b>URL</b> вставьте ссылку. Нажмите <b>Создать</b>.</p>
      <figure>
        <svg viewBox="0 0 270 210" role="img" aria-label="Форма нового профиля: имя, тип Удалённый, URL">
          <rect x="35" y="8" width="200" height="194" rx="16" fill="var(--card)"
                stroke="var(--line)"/>
          <text x="52" y="34" font-size="13" font-weight="600" fill="var(--ink)">Новый профиль</text>
          <rect x="52" y="46" width="166" height="28" rx="8" fill="var(--soft)"/>
          <text x="62" y="64" font-size="11" fill="var(--dim)">Имя: VPN</text>
          <rect x="52" y="82" width="80" height="26" rx="8" fill="var(--soft)"/>
          <text x="62" y="99" font-size="11" fill="var(--dim)">Локальный</text>
          <rect x="138" y="82" width="80" height="26" rx="8" fill="var(--accent)"/>
          <text x="148" y="99" font-size="11" font-weight="600" fill="#fff">Удалённый</text>
          <rect x="52" y="116" width="166" height="28" rx="8" fill="var(--bg)"
                stroke="var(--accent)" stroke-width="1.5"/>
          <text x="62" y="134" font-size="11" fill="var(--accent)">URL: https://…/sub/a1b2…</text>
          <rect x="138" y="160" width="80" height="28" rx="9" fill="var(--accent)"/>
          <text x="178" y="178" font-size="11" font-weight="600" text-anchor="middle"
                fill="#fff">Создать</text>
        </svg>
        <figcaption>Тип «Удалённый», ссылка — в поле URL</figcaption>
      </figure>
    </li>

    <li>
      <b>Включите</b>
      <p>Вернитесь на главный экран и нажмите круглую кнопку запуска внизу
         справа. Телефон один раз спросит разрешение на VPN — согласитесь.
         Вверху появится значок <b>VPN</b> или ключика.</p>
    </li>

    <li>
      <b>Проверьте</b>
      <p>Откройте YouTube. Видео играет — готово. Приложение sing-box можно
         закрыть: VPN останется включённым и после перезагрузки телефона
         включится, когда вы снова нажмёте кнопку.</p>
    </li>
  </ol>

  <h2>Что работает само</h2>
  <div class="got">
    <div>
      <b>Российское — напрямую</b>
      <p>Сайты в зонах .ru и .рф, ВКонтакте, Яндекс, маркетплейсы и
         российские адреса идут мимо VPN. На Android приложения банков,
         Госуслуг, Налогов, Ozon, Wildberries, Яндекса и операторов связи
         вообще не видят VPN — им ничего не мешает.</p>
    </div>
  </div>
  <div class="got">
    <div>
      <b>Два канала связи</b>
      <p>Основной — <b>Hysteria2</b>: быстрый и устойчивый на мобильном
         интернете. Запасной — <b>VLESS</b>. Если оператор перекроет основной,
         телефон сам перейдёт на запасной за минуту — ничего нажимать не нужно.</p>
    </div>
  </div>
  <div class="got">
    <div>
      <b>Настройки обновляются раз в сутки</b>
      <p>Улучшения и новые списки сайтов приходят сами. Обновить сразу:
         в блоке <b>Профили</b> нажмите на стрелочку обновления у профиля.</p>
    </div>
  </div>

  <div class="note warn">
    <b>Одна ссылка — одно устройство</b>
    Ссылка привязывается к первому телефону, на который её поставили.
    Если ею одновременно пользуются на двух устройствах, сервер это видит и
    отключает то, что подключилось позже, на 30 минут. Смена Wi-Fi на
    мобильный интернет за второе устройство не считается.
    Нужно ещё одно устройство — попросите отдельную ссылку, это бесплатно.
  </div>

  <h2>Способ 2 · Файл AmneziaWG</h2>
  <p class="sub">Только если файл прислали: для роутера или если первый способ
     не заработал.</p>

  <ol>
    <li>
      <b>Установите приложение AmneziaWG</b>
      <p>Именно <b>AmneziaWG</b>, а не <b>Amnezia VPN</b> — это разные приложения.</p>
      <div class="apps">
        <a href="https://play.google.com/store/apps/details?id=org.amnezia.awg">Android</a>
        <a href="https://apps.apple.com/app/amneziawg/id6478942365">iPhone и iPad</a>
      </div>
    </li>
    <li>
      <b>Откройте файл в приложении</b>
      <p>Нажмите на файл в сообщении → <b>Открыть в AmneziaWG</b>. Если
         такого пункта нет: сохраните файл, в AmneziaWG нажмите <b>+</b> →
         <b>Импорт из файла</b>.</p>
    </li>
    <li>
      <b>Включите переключатель</b>
      <p>Сдвиньте переключатель у появившегося подключения и разрешите VPN.</p>
    </li>
  </ol>

  <div class="note plain">
    <b>Чем файл хуже ссылки</b>
    Он не обновляется сам: если сервер переедет, файл придётся попросить
    заново. И через него идёт весь трафик, включая российский.
  </div>

  <h2>Если что-то не так</h2>

  <details>
    <summary>VPN включён, но сайты не открываются или всё медленно</summary>
    <p>Если канал перекрыт полностью, телефон переключится сам. Но бывает,
       что оператор канал не перекрывает, а душит по скорости — этого
       автоматика не видит. Тогда переключите вручную: на главном экране
       sing-box нажмите <b>Группы</b> (значок рядом с кнопкой остановки) и в
       группе <b>proxy</b> выберите <b>vless</b>. Вернуть автоматику — выбрать
       там же <b>auto</b>.</p>
    <p>Не помогло — выключите и включите VPN, затем обновите профиль
       стрелочкой. Если и это не помогло, напишите тому, кто дал ссылку.</p>
  </details>

  <details>
    <summary>Работало, а потом отключилось и полчаса не подключается</summary>
    <p>Скорее всего, вашей ссылкой пользуется кто-то ещё — на другом
       устройстве. Сервер отключает лишнее на 30 минут. Если вы никому
       ссылку не давали, напишите тому, кто её выдал: её заменят.</p>
  </details>

  <details>
    <summary>Ссылка не добавляется, профиль не скачивается</summary>
    <p>Проверьте, что скопировали ссылку целиком. Попробуйте через Wi-Fi:
       профиль скачается один раз и дальше будет работать в любой сети.</p>
    <p>Ошибка про <b>другое устройство</b> означает, что ссылку уже
       поставили на другой телефон. Сменили телефон — попросите снять
       привязку, и та же ссылка встанет на новый.</p>
  </details>

  <details>
    <summary>Банк или Госуслуги капризничают</summary>
    <p>На Android основные банки и госсервисы уже идут мимо VPN. Если
       капризничает приложение не из списка: в sing-box откройте
       <b>Параметры → Перезапись профиля → Прокси для отдельных приложений</b> и уберите его из VPN, а тому,
       кто дал ссылку, напишите название — его добавят для всех.
       На iPhone такой настройки нет — выключите VPN на минуту.</p>
  </details>

  <details>
    <summary>sing-box не запускается или пишет ошибку</summary>
    <p>Обновите приложение в магазине — старые версии не понимают новые
       настройки. Не помогло — поставьте <b>Hiddify</b>: оно понимает ту же
       ссылку (+ → <b>Добавить из буфера обмена</b>). Текст ошибки пришлите
       тому, кто дал ссылку.</p>
  </details>

  <details>
    <summary>Мне дали только ссылку vless://</summary>
    <p>Это упрощённый вариант: работает в любом приложении (sing-box,
       Hiddify, v2rayNG, v2RayTun), но через VPN идёт весь трафик, включая
       банки. Чтобы российское шло напрямую, попросите ссылку на подписку.</p>
  </details>

  <div class="note warn">
    <b>Ссылка — это ключ</b>
    Не публикуйте и не пересылайте её. Если ею воспользуется кто-то ещё,
    VPN начнёт отключаться у вас обоих.
  </div>

  <footer>Личный VPN · настройки обновляются автоматически</footer>
</main>
</body>
</html>`;
}
