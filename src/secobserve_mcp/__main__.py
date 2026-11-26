"""Entry point for the SecObserve MCP server.

Defaults to stdio, which is what a local MCP client expects. Streamable HTTP is
available for a shared deployment; it binds to 127.0.0.1 unless told otherwise,
because an MCP server carries the caller's SecObserve credentials. HTTP has no
authentication of its own, so it refuses to start on a credential read from the
environment unless --shared-identity accepts that every caller shares it.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from . import __version__
from .config import (
    ENV_ALLOW_DELETE,
    ENV_ALLOWED_HOSTS,
    ENV_API_TOKEN,
    ENV_AUDIT_LOG,
    ENV_BASE_URL,
    ENV_EXPORT_DIR,
    ENV_IMPORT_DIR,
    ENV_JWT,
    ENV_READ_ONLY,
    ENV_TIMEOUT,
    ENV_VERIFY_SSL,
    ConfigError,
    _bool_env,
    get_config,
)

if TYPE_CHECKING:
    from mcp.server.transport_security import TransportSecuritySettings

EPILOG = f"""environment:
  {ENV_BASE_URL}     SecObserve base URL without /api (default http://localhost:8000)
  {ENV_API_TOKEN}    user or product API token (recommended)
  {ENV_JWT}          JWT, as an alternative to an API token
  {ENV_TIMEOUT}      request timeout in seconds (default 60; raise it for imports and scans)
  {ENV_VERIFY_SSL}   set to false only for a self-signed dev certificate
  {ENV_READ_ONLY}    every write is refused by default; set to false to allow writes
  {ENV_ALLOW_DELETE} set to true to enable secobserve_delete and bulk-delete actions (deletes cascade)
  {ENV_IMPORT_DIR}   directory uploads may be read from; uploads are off until it is set
  {ENV_EXPORT_DIR}   directory exports are written to (default: ./secobserve-exports)
  {ENV_AUDIT_LOG}    one JSON line per tool call on stderr; set to false to switch it off
  {ENV_ALLOWED_HOSTS} Host names --transport http answers to besides localhost, comma-separated

A boolean is true/false, 1/0, yes/no or on/off. Any other value is refused at startup.
"""


def _load_tools() -> None:
    # Imported for the @mcp.tool and @mcp.prompt registrations they perform.
    from . import prompts, tools_crud, tools_workflows  # noqa: F401


TOKEN_PLACEHOLDER = "<your-api-token>"

SHARED_IDENTITY_FLAG = "--shared-identity"

CLIENTS = ("claude", "codex", "json", "vscode")

# Once `uv tool install` has created a persistent environment, a bare `uvx secobserve-mcp` runs that pinned copy
# forever. `@latest` revalidates against the index on every launch; `--isolated` only skips the tool environment and
# may still serve a cached build.
PACKAGE_SPEC = "secobserve-mcp@latest"

PYPI_JSON_URL = "https://pypi.org/pypi/secobserve-mcp/json"
PYPI_TIMEOUT_SECONDS = 3.0


def _print_config(client: str) -> int:
    """Print a registration snippet for one MCP client.

    The base URL comes from the environment; the token never does, because this output gets pasted places.
    """
    base_url = get_config().base_url
    env = {ENV_BASE_URL: base_url, ENV_API_TOKEN: TOKEN_PLACEHOLDER}

    if client == "claude":
        flags = " ".join(f"--env {k}={v}" for k, v in env.items())
        print(f"claude mcp add secobserve {flags} -- uvx {PACKAGE_SPEC}")
    elif client == "codex":
        pairs = ", ".join(f'{k} = "{v}"' for k, v in env.items())
        print("[mcp_servers.secobserve]")
        print('command = "uvx"')
        print(f'args = ["{PACKAGE_SPEC}"]')
        print(f"env = {{ {pairs} }}")
    else:
        # VS Code keys this "servers"; everyone else kept "mcpServers".
        key = "servers" if client == "vscode" else "mcpServers"
        block = {key: {"secobserve": {"command": "uvx", "args": [PACKAGE_SPEC], "env": env}}}
        print(json.dumps(block, indent=2))

    print(f"\nReplace {TOKEN_PLACEHOLDER}; create one with", file=sys.stderr)
    print(f"  curl -X POST {base_url}/api/authentication/create_user_api_token/ \\", file=sys.stderr)
    print('       -H "Content-Type: application/json" \\', file=sys.stderr)
    print('       -d \'{"username": "you", "password": "...", "name": "mcp"}\'', file=sys.stderr)
    return 0


def _runs_from_uv_tool_env() -> bool:
    """Whether this interpreter is a persistent `uv tool install` environment rather than an ephemeral uvx one.

    uv writes uv-receipt.toml at the root of a tool environment and nowhere else; an ephemeral uvx run lives under
    the uv cache with no receipt.
    """
    return (Path(sys.prefix) / "uv-receipt.toml").is_file()


async def _latest_release() -> str | None:
    """The newest version on PyPI, or None when it cannot be determined. Never raises, never called on server start."""
    import httpx

    try:
        async with httpx.AsyncClient(timeout=PYPI_TIMEOUT_SECONDS) as http:
            response = await http.get(PYPI_JSON_URL)
            response.raise_for_status()
            latest = response.json()["info"]["version"]
        return latest if isinstance(latest, str) else None
    except Exception:  # noqa: BLE001 - advisory only; --check must still report on SecObserve
        return None


async def _report_install() -> None:
    latest = await _latest_release()
    if latest is None:
        print(f"  secobserve-mcp: {__version__} (latest release could not be determined)", file=sys.stderr)
    elif latest == __version__:
        print(f"  secobserve-mcp: {__version__} (latest)")
    else:
        print(f"  secobserve-mcp: {__version__} (PyPI has {latest})")

    if _runs_from_uv_tool_env():
        print("  install: a uv tool environment, which `uvx secobserve-mcp` keeps running instead of the latest")
        print(f"  fix: uv tool upgrade secobserve-mcp, or point the client at `uvx {PACKAGE_SPEC}`")


async def _check() -> int:
    from .client import close_client, request

    config = get_config()
    try:
        version = await request("GET", "/status/version/")
        user = await request("GET", "/users/me/")
        print(f"Connected to {config.base_url}")
        print(f"  version: {version.get('version', version)}")
        print(f"  authenticated as: {user.get('username', '?')} (superuser: {user.get('is_superuser', False)})")
        print(f"  read-only: {config.read_only}, deletes enabled: {config.allow_delete}")
        status = 0
    except Exception as exc:  # noqa: BLE001 - the message is the whole point here
        print(f"Check failed: {exc}", file=sys.stderr)
        status = 1
    finally:
        await close_client()

    await _report_install()
    return status


def _shared_identity_refusal(host: str, port: int) -> str:
    """Why an HTTP start on a process-wide credential is refused, and the exact command line that accepts it."""
    return (
        f"Refusing to start: --transport http serves {host}:{port} with no authentication of its own, and the "
        f"credential in {ENV_API_TOKEN}/{ENV_JWT} makes every caller of that port act as one SecObserve identity "
        "with all of that token's permissions.\n"
        "\n"
        "Better: an authenticating gateway in front, so each caller reaches SecObserve as themselves.\n"
        "For one user: drop --transport http and run over stdio with that user's own token.\n"
        f"To accept one shared identity: restart with the whole command line, which then refuses every write.\n"
        "\n"
        f"  secobserve-mcp --transport http --host {host} --port {port} {SHARED_IDENTITY_FLAG}\n"
        "\n"
        "A container needs the whole line too, because arguments to `docker run` replace CMD."
    )


LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "[::1]")


def _cleartext_warning(base_url: str) -> str | None:
    """A warning when the token would cross a network unencrypted, None when it stays on this machine or uses TLS."""
    parts = urlsplit(base_url)
    host = parts.hostname or ""
    if parts.scheme != "http" or host == "localhost" or host.endswith(".localhost"):
        return None
    try:
        if ipaddress.ip_address(host).is_loopback:
            return None
    except ValueError:
        pass
    return (
        f"Warning: {ENV_BASE_URL} is http:// to {host}, so the credential and every finding cross the network "
        "unencrypted. Use https://; plain http is for a SecObserve on this machine."
    )


def _transport_security(extra_hosts: tuple[str, ...]) -> TransportSecuritySettings:
    """Host and Origin checks that hold on every bind address.

    The SDK switches them on by itself for a loopback bind only. A container has to bind 0.0.0.0, and there the SDK
    answers any Host and any Origin, so a web page that rebinds its own name to this port reads SecObserve through
    the browser of whoever opened it. Loopback names always pass, which is what a published container port is
    reached by; every other name a client uses is the operator's to list.
    """
    from mcp.server.transport_security import TransportSecuritySettings

    hosts: list[str] = []
    origins: list[str] = []
    for host in (*LOOPBACK_HOSTS, *extra_hosts):
        has_port = ":" in host and not host.endswith("]") and host.rpartition(":")[2].isdigit()
        for name in (host,) if has_port else (host, f"{host}:*"):
            hosts.append(name)
            origins.extend((f"http://{name}", f"https://{name}"))
    return TransportSecuritySettings(enable_dns_rebinding_protection=True, allowed_hosts=hosts, allowed_origins=origins)


def _force_read_only() -> None:
    """Refuse writes for the rest of the process, through the switch client.request already enforces."""
    os.environ[ENV_READ_ONLY] = "true"
    get_config.cache_clear()


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="secobserve-mcp",
        description="MCP server exposing the SecObserve REST API.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio", help="default: stdio")
    parser.add_argument("--host", default="127.0.0.1", help="bind address for --transport http")
    parser.add_argument("--port", type=int, default=8931, help="port for --transport http")
    parser.add_argument(
        SHARED_IDENTITY_FLAG,
        action="store_true",
        help=(
            f"accept that every caller of --transport http acts as the one identity in {ENV_API_TOKEN}/{ENV_JWT} "
            "on a port this server does not authenticate; forces read-only for the process"
        ),
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify connectivity, credentials and that this install is current, then exit",
    )
    parser.add_argument(
        "--print-config",
        choices=CLIENTS,
        metavar="CLIENT",
        help=f"print a registration snippet for one of: {', '.join(CLIENTS)}",
    )
    parser.add_argument("--version", action="version", version=f"secobserve-mcp {__version__}")
    args = parser.parse_args()

    # Before the credential check: this is how you find out how to supply them.
    if args.print_config:
        try:
            return _print_config(args.print_config)
        except ConfigError as exc:
            print(f"Configuration error: {exc}", file=sys.stderr)
            return 2

    _load_tools()
    from .app import mcp

    try:
        config = get_config()
        # Read per call by the audit middleware, which must not fail a call; an unreadable value stops here instead.
        _bool_env(ENV_AUDIT_LOG, True)
        _ = config.auth_header
    except ConfigError as exc:
        # stdio clients swallow stdout, so configuration problems go to stderr.
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    if warning := _cleartext_warning(config.base_url):
        print(warning, file=sys.stderr)

    if args.check:
        return asyncio.run(_check())

    if args.transport == "http":
        allowed_hosts = config.allowed_hosts
        if config.api_token or config.jwt:
            if not args.shared_identity:
                print(_shared_identity_refusal(args.host, args.port), file=sys.stderr)
                return 2
            _force_read_only()
            print(
                f"{SHARED_IDENTITY_FLAG}: every caller of {args.host}:{args.port} acts as the identity in "
                f"{ENV_API_TOKEN}/{ENV_JWT}; this process refuses every write.",
                file=sys.stderr,
            )
        if args.host not in ("127.0.0.1", "localhost", "::1"):
            also = f" and {', '.join(allowed_hosts)}" if allowed_hosts else ""
            print(
                f"Bound to {args.host}:{args.port}; requests are answered for the Host names localhost, 127.0.0.1, "
                f"[::1]{also}. A client using any other name gets 421 until it is listed in {ENV_ALLOWED_HOSTS}.",
                file=sys.stderr,
            )
        mcp.run(
            transport="streamable-http",
            host=args.host,
            port=args.port,
            stateless_http=True,
            json_response=True,
            transport_security=_transport_security(allowed_hosts),
        )
    else:
        mcp.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
