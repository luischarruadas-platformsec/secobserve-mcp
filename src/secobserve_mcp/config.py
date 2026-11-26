"""Environment-driven configuration for the SecObserve MCP server."""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import lru_cache

ENV_BASE_URL = "SECOBSERVE_BASE_URL"
ENV_API_TOKEN = "SECOBSERVE_API_TOKEN"
ENV_JWT = "SECOBSERVE_JWT"
ENV_TIMEOUT = "SECOBSERVE_TIMEOUT"
ENV_VERIFY_SSL = "SECOBSERVE_VERIFY_SSL"
ENV_READ_ONLY = "SECOBSERVE_READ_ONLY"
ENV_ALLOW_DELETE = "SECOBSERVE_ALLOW_DELETE"
ENV_EXPORT_DIR = "SECOBSERVE_EXPORT_DIR"
ENV_IMPORT_DIR = "SECOBSERVE_IMPORT_DIR"
ENV_AUDIT_LOG = "SECOBSERVE_AUDIT_LOG"
ENV_ALLOWED_HOSTS = "SECOBSERVE_ALLOWED_HOSTS"

CREDENTIAL_HEADER = "X-SecObserve-Token"
# Bearer is SecObserve's OIDC path: it validates the token against the IdP's JWKS and resolves the real user,
# so a gateway can forward the caller's own access token untouched. It is accepted per request only -- an
# environment-configured Bearer would be a short-lived token frozen at startup.
CREDENTIAL_SCHEMES = ("APIToken", "JWT", "Bearer")

DEFAULT_BASE_URL = "http://localhost:8000"
DEFAULT_TIMEOUT = 60.0


class ConfigError(RuntimeError):
    """Raised when the server is started without usable credentials, or with a setting it cannot read."""


_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off"})


def _bool_env(name: str, default: bool) -> bool:
    """Read a switch, refusing a value that is neither on nor off.

    Every switch here guards something, and a typo read as "off" picks the unsafe side for three of them in
    silence: writes stay on, TLS verification goes off, the audit log stops.
    """
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    value = raw.strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise ConfigError(f"{name}={raw!r} is not a boolean. Set it to true or false (1/0, yes/no and on/off also work).")


# A name or address with an optional port, as it appears in a Host header: no scheme, no path, no wildcard.
_HOST = re.compile(r"^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?)(:\d{1,5})?$")


def _hosts_env(name: str) -> tuple[str, ...]:
    """Read a comma-separated list of Host header values, refusing an entry that could never match one."""
    hosts = tuple(entry.strip() for entry in os.environ.get(name, "").split(",") if entry.strip())
    for host in hosts:
        if not _HOST.match(host):
            raise ConfigError(
                f"{name} entry {host!r} is not a host name. Give the names clients put in the Host header, "
                "comma-separated, each as name or name:port -- no scheme, no path, no wildcard."
            )
    return hosts


@dataclass(frozen=True)
class Config:
    base_url: str
    # Out of the repr, so a config that ends up in a log line or a traceback does not carry the credential.
    api_token: str | None = field(repr=False)
    jwt: str | None = field(repr=False)
    timeout: float
    verify_ssl: bool
    read_only: bool
    allow_delete: bool
    export_dir: str
    import_dir: str | None
    allowed_hosts: tuple[str, ...]

    @property
    def auth_header(self) -> str:
        # API tokens are the documented integration path; JWT is accepted for
        # short-lived interactive use with a user's own frontend session.
        if self.api_token:
            return f"APIToken {self.api_token}"
        if self.jwt:
            return f"JWT {self.jwt}"
        raise ConfigError(
            f"No credentials configured. Set {ENV_API_TOKEN} (recommended) or {ENV_JWT}. "
            "A user API token is created via POST /api/authentication/create_user_api_token/."
        )

    @property
    def api_root(self) -> str:
        return f"{self.base_url}/api"


@lru_cache(maxsize=1)
def get_config() -> Config:
    base_url = os.environ.get(ENV_BASE_URL, DEFAULT_BASE_URL).rstrip("/")
    try:
        timeout = float(os.environ.get(ENV_TIMEOUT, DEFAULT_TIMEOUT))
    except ValueError as exc:
        raise ConfigError(f"{ENV_TIMEOUT} must be a number of seconds") from exc

    return Config(
        base_url=base_url,
        api_token=os.environ.get(ENV_API_TOKEN) or None,
        jwt=os.environ.get(ENV_JWT) or None,
        timeout=timeout,
        verify_ssl=_bool_env(ENV_VERIFY_SSL, True),
        # Scanner text reaches the agent as untrusted input, so writing is something an operator switches on.
        read_only=_bool_env(ENV_READ_ONLY, True),
        # Deletes cascade in SecObserve, so they stay off unless switched on.
        allow_delete=_bool_env(ENV_ALLOW_DELETE, False),
        export_dir=os.environ.get(ENV_EXPORT_DIR) or os.path.join(os.getcwd(), "secobserve-exports"),
        # Uploads are confined to one tree so a crafted path cannot push arbitrary local files into SecObserve.
        # There is no default: the working directory is whatever the client launched from, often a home
        # directory or a repository full of files that are not scan reports.
        import_dir=os.environ.get(ENV_IMPORT_DIR) or None,
        allowed_hosts=_hosts_env(ENV_ALLOWED_HOSTS),
    )


# Config is cached for the process lifetime, so a credential that differs per caller cannot live on it.
_request_credential: ContextVar[str | None] = ContextVar("secobserve_request_credential", default=None)


@contextmanager
def request_credential(value: str | None) -> Iterator[None]:
    """Make `value` the credential inside this block; None leaves the environment's in force."""
    token = _request_credential.set(value)
    try:
        yield
    finally:
        _request_credential.reset(token)


def request_auth_header() -> str:
    """The Authorization value for the call in flight: the credential the request carried, else the environment's.

    Raises:
        ConfigError: when the request carried a credential this server cannot read, or when neither source has one.
    """
    raw = _request_credential.get()
    if raw is None:
        return get_config().auth_header

    scheme, _, token = raw.partition(" ")
    if scheme not in CREDENTIAL_SCHEMES or not token.strip():
        raise ConfigError(
            f"{CREDENTIAL_HEADER} is malformed: send '<scheme> <token>', scheme {' or '.join(CREDENTIAL_SCHEMES)}. "
            "The call was refused rather than fall back to the server's own credential, "
            "which would attribute the action to the service account."
        )
    return raw
