"""HTTP-клиент к трём внешним API — напрямую или через Cloudflare-релей.

С российского хостинга api.telegram.org недоступен, а доступность api.upcloud.com
не гарантирована, поэтому по умолчанию все запросы идут через Worker-релей.
"""

from __future__ import annotations

import time
from typing import Any

import requests

from . import log

logger = log.get("relay")

# Единственные хосты, к которым агент вообще обращается. Тот же список
# продублирован белым списком в relay/worker.js.
UPSTREAMS = {
    "tg": "https://api.telegram.org",
    "uc": "https://api.upcloud.com",
    "cf": "https://api.cloudflare.com",
}

RETRYABLE_STATUS = {429, 500, 502, 503, 504}


class RelayError(RuntimeError):
    pass


class Relay:
    def __init__(
        self,
        urls: list[str],
        key: str,
        *,
        prefer_direct: bool = False,
        allow_direct_fallback: bool = False,
        timeout: float = 30.0,
        attempts_per_endpoint: int = 2,
    ):
        self.urls = [u.rstrip("/") for u in urls if u.strip()]
        self.key = key
        self.prefer_direct = prefer_direct
        self.allow_direct_fallback = allow_direct_fallback
        self.timeout = timeout
        self.attempts_per_endpoint = attempts_per_endpoint
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "vpn-ip-rotator/1.0"
        self._healthy_url: str | None = None

    # --- построение списка кандидатов ---------------------------------------

    def _endpoints(self, upstream: str, path: str) -> list[tuple[str, dict[str, str]]]:
        path = path if path.startswith("/") else "/" + path
        direct = (UPSTREAMS[upstream] + path, {})
        relayed = [
            (f"{url}/{upstream}{path}", {"X-Relay-Key": self.key})
            for url in self._ordered_urls()
        ]
        if self.prefer_direct:
            return [direct] + relayed
        return relayed + ([direct] if self.allow_direct_fallback or not relayed else [])

    def _ordered_urls(self) -> list[str]:
        """Последний сработавший релей пробуем первым."""
        if self._healthy_url and self._healthy_url in self.urls:
            return [self._healthy_url] + [u for u in self.urls if u != self._healthy_url]
        return list(self.urls)

    # --- запрос -------------------------------------------------------------

    def request(
        self,
        upstream: str,
        method: str,
        path: str,
        *,
        json: Any = None,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> requests.Response:
        last_error: Exception | None = None
        last_response: requests.Response | None = None

        for url, extra in self._endpoints(upstream, path):
            merged = {**(headers or {}), **extra}
            for attempt in range(self.attempts_per_endpoint):
                try:
                    response = self.session.request(
                        method.upper(),
                        url,
                        json=json,
                        headers=merged,
                        params=params,
                        timeout=timeout or self.timeout,
                    )
                except requests.RequestException as exc:
                    last_error = exc
                    logger.debug("%s %s: транспорт не отвечает (%s)", method, url, exc.__class__.__name__)
                    time.sleep(1.5 * (attempt + 1))
                    continue

                if response.status_code in RETRYABLE_STATUS and attempt + 1 < self.attempts_per_endpoint:
                    last_response = response
                    time.sleep(2.0 * (attempt + 1))
                    continue

                # 4xx — это ответ самого API, менять транспорт бессмысленно.
                if response.status_code not in RETRYABLE_STATUS:
                    if extra:
                        self._healthy_url = url.rsplit(f"/{upstream}", 1)[0]
                    return response

                last_response = response
                break

        if last_response is not None:
            return last_response
        raise RelayError(f"{upstream}{path}: ни один канал не ответил ({last_error})")

    def health(self) -> dict[str, str]:
        """Быстрая проверка каналов для /check."""
        result: dict[str, str] = {}
        for url in self.urls:
            try:
                response = self.session.get(
                    f"{url}/healthz", headers={"X-Relay-Key": self.key}, timeout=10
                )
                result[url] = "ok" if response.ok else f"HTTP {response.status_code}"
            except requests.RequestException as exc:
                result[url] = exc.__class__.__name__
        return result
