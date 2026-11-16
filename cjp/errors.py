"""
Plain-language errors with the fix (Plan P2.10).

Before this, a dropped SSH tunnel surfaced as an httpx ConnectError traceback
from deep inside the indexer client, and a bad API key as a 401 traceback
after the batch had started. Now `cjp` catches the failures it knows, prints
one line saying what is wrong and the command that fixes it, and exits 1.
`CJP_DEBUG=1` shows the traceback as well. `cjp doctor` uses the same fix
texts, so a check and the error it predicts read alike.

Only failures with a known cause and fix are translated; anything else is a
bug and keeps its traceback.
"""

import os
from urllib.parse import urlparse

from cjp import config


def tunnel_command() -> str:
    """The SSH tunnel to the Wazuh indexer (9200) and manager API (55000)
    (wazuh-and-vm-notes §8)."""
    host = config.VM_HOST or "<vm-ip>"
    return f"ssh -N -L 9200:localhost:9200 -L 55000:localhost:55000 {config.VM_USER}@{host}"


def ssh_fix() -> str:
    if not config.VM_HOST:
        return "set VM_HOST in .env (see .env.example)"
    return (f"start the VM in UTM, then check key-based SSH: ssh {config.VM_USER}@{config.VM_HOST} "
            f"(no key yet: ssh-copy-id {config.VM_USER}@{config.VM_HOST})")


def _service(url: str) -> str:
    """Which Wazuh service a URL points at."""
    if url.startswith(config.INDEXER_URL.rstrip("/")):
        return "Wazuh indexer"
    if url.startswith(config.WAZUH_URL.rstrip("/")):
        return "Wazuh manager API"
    return urlparse(url).netloc or url


def _credentials(url: str) -> str:
    if url.startswith(config.INDEXER_URL.rstrip("/")):
        return "INDEXER_USER / INDEXER_PASS"
    return "WAZUH_USER / WAZUH_PASS"


def explain(exc: BaseException) -> str | None:
    """'what is wrong → what to do' for a known failure, else None."""
    import httpx

    from cjp.cache import CacheMiss

    if isinstance(exc, config.ConfigError):
        return f"{exc}\n  fix config/settings.yaml or .env (documented in .env.example), then: cjp doctor"
    if isinstance(exc, CacheMiss):
        return ("--cache-only: an alert has no cached response, so nothing was run. "
                "Drop --cache-only to call the API (the count of paid calls is printed first)")
    if isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout)):
        try:
            url = str(exc.request.url)
        except RuntimeError:    # raised without a request attached
            url = ""
        return (f"{_service(url)} unreachable at {url or 'its URL'}. Is the SSH tunnel up? "
                f"Run (and leave open): {tunnel_command()}")
    if isinstance(exc, httpx.HTTPStatusError):
        url, code = str(exc.request.url), exc.response.status_code
        if code in (401, 403):
            return (f"{_service(url)} rejected the credentials (HTTP {code}): "
                    f"check {_credentials(url)} in .env")
        return f"{_service(url)} answered HTTP {code} for {url}"

    try:
        import anthropic
    except ImportError:     # the evaluate path never needs it
        return None
    if isinstance(exc, anthropic.AuthenticationError):
        return "the Claude API rejected ANTHROPIC_API_KEY: set a valid key in .env, then: cjp doctor"
    if isinstance(exc, anthropic.PermissionDeniedError):
        return f"this API key may not use that model or feature: {exc.message}"
    if isinstance(exc, anthropic.NotFoundError):
        return (f"the Claude API does not know that model ({exc.message}): check the IDs in "
                "config/settings.yaml `models` against the Anthropic models list (cjp doctor)")
    if isinstance(exc, anthropic.BadRequestError):
        return (f"the Claude API rejected the request: {exc.message}. A parameter this model "
                "does not accept? Check its entry in config/settings.yaml `models`")
    if isinstance(exc, anthropic.RateLimitError):
        return ("rate-limited by the Claude API after every retry: wait a few minutes, then "
                "resume (finished alerts are kept; cached answers are free)")
    if isinstance(exc, (anthropic.APIConnectionError, anthropic.APITimeoutError)):
        return ("cannot reach the Claude API after every retry (network down?): resume later; "
                "finished alerts are kept and cached answers are free")
    if isinstance(exc, anthropic.InternalServerError):
        return f"the Claude API failed (HTTP {exc.status_code}) after every retry: resume later"
    return None


def debug() -> bool:
    return os.getenv("CJP_DEBUG", "") not in ("", "0")
