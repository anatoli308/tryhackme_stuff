from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests


@dataclass
class HttpResult:
    ok: bool
    status_code: int
    text: str
    headers: dict[str, str]
    url: str


class HttpClient:
    def __init__(self, base_url: str, timeout: int = 10) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

    def url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"

    def request(self, method: str, path: str, **kwargs: Any) -> HttpResult:
        target_url = self.url(path)
        try:
            response = self.session.request(
                method=method,
                url=target_url,
                timeout=self.timeout,
                allow_redirects=kwargs.pop("allow_redirects", True),
                **kwargs,
            )
            return HttpResult(
                ok=response.ok,
                status_code=response.status_code,
                text=response.text,
                headers={k: v for k, v in response.headers.items()},
                url=response.url,
            )
        except requests.exceptions.RequestException as exc:
            return HttpResult(
                ok=False,
                status_code=0,
                text=str(exc),
                headers={},
                url=target_url,
            )
