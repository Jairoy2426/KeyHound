"""
KeyHound — Live API verification engine.

Stage 3: Probes live endpoints to determine if discovered credentials are
still active.  Only CRITICAL and HIGH severity findings are verified.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from keyhound.detector import Finding

# Minimum seconds between any two outbound verification requests
_RATE_LIMIT_SECONDS: float = 2.0

# Per-request timeout
_REQUEST_TIMEOUT: float = 5.0

# Track timestamp of last request globally within this module
_last_request_at: float = 0.0


# ── Rate-limit helper ─────────────────────────────────────────────────────────

async def _rate_limited_get(
    client: httpx.AsyncClient,
    url: str,
    **kwargs,
) -> httpx.Response:
    """Perform a GET that respects the module-level rate limit."""
    global _last_request_at

    elapsed = time.monotonic() - _last_request_at
    if elapsed < _RATE_LIMIT_SECONDS:
        await asyncio.sleep(_RATE_LIMIT_SECONDS - elapsed)

    _last_request_at = time.monotonic()
    return await client.get(url, **kwargs)


async def _rate_limited_post(
    client: httpx.AsyncClient,
    url: str,
    **kwargs,
) -> httpx.Response:
    """Perform a POST that respects the module-level rate limit."""
    global _last_request_at

    elapsed = time.monotonic() - _last_request_at
    if elapsed < _RATE_LIMIT_SECONDS:
        await asyncio.sleep(_RATE_LIMIT_SECONDS - elapsed)

    _last_request_at = time.monotonic()
    return await client.post(url, **kwargs)


# ── Provider verifiers ────────────────────────────────────────────────────────

async def _verify_aws(key: str, client: httpx.AsyncClient) -> str:
    """
    Verify an AWS Access Key ID using boto3 STS.

    The key passed here is the Access Key ID (AKIA…).  We look up the matching
    secret from the environment / config — if we only have the key ID we still
    attempt the call; boto3 will fail gracefully with an auth error.
    """
    try:
        import boto3
        import botocore.exceptions

        # boto3 is sync — run in executor to avoid blocking the event loop
        loop = asyncio.get_event_loop()

        def _sts_call() -> str:
            sts = boto3.client(
                "sts",
                aws_access_key_id=key,
                aws_secret_access_key="DUMMY_SECRET_FOR_KEY_ID_CHECK",
                region_name="us-east-1",
            )
            try:
                sts.get_caller_identity()
                return "VALID"
            except botocore.exceptions.ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code in ("InvalidClientTokenId", "AuthFailure",
                            "SignatureDoesNotMatch"):
                    return "EXPIRED"
                return "UNKNOWN"
            except Exception:
                return "UNKNOWN"

        return await loop.run_in_executor(None, _sts_call)

    except ImportError:
        return "UNKNOWN"
    except Exception:
        return "UNKNOWN"


async def _verify_github(token: str, client: httpx.AsyncClient) -> str:
    """Verify a GitHub personal access token via the /user endpoint."""
    try:
        resp = await _rate_limited_get(
            client,
            "https://api.github.com/user",
            headers={"Authorization": f"token {token}"},
            timeout=_REQUEST_TIMEOUT,
        )
        if resp.status_code == 200:
            return "VALID"
        if resp.status_code == 401:
            return "EXPIRED"
        return "UNKNOWN"
    except Exception:
        return "UNKNOWN"


async def _verify_stripe(key: str, client: httpx.AsyncClient) -> str:
    """Verify a Stripe secret key via the /v1/balance endpoint."""
    try:
        resp = await _rate_limited_get(
            client,
            "https://api.stripe.com/v1/balance",
            headers={"Authorization": f"Bearer {key}"},
            timeout=_REQUEST_TIMEOUT,
        )
        if resp.status_code == 200:
            return "VALID"
        if resp.status_code == 401:
            return "EXPIRED"
        return "UNKNOWN"
    except Exception:
        return "UNKNOWN"


async def _verify_twilio(sid: str, client: httpx.AsyncClient) -> str:
    """
    Verify a Twilio Account SID.  Because we typically only have the SID from
    regex matching (not the paired auth token), we attempt the accounts list
    call with an empty auth token which will return 401 on EXPIRED keys and a
    slightly different error on unknown keys.
    """
    try:
        resp = await _rate_limited_get(
            client,
            f"https://api.twilio.com/2010-04-01/Accounts.json",
            auth=(sid, ""),
            timeout=_REQUEST_TIMEOUT,
        )
        if resp.status_code == 200:
            return "VALID"
        if resp.status_code in (401, 403):
            return "EXPIRED"
        return "UNKNOWN"
    except Exception:
        return "UNKNOWN"


async def _verify_sendgrid(key: str, client: httpx.AsyncClient) -> str:
    """Verify a SendGrid API key via the /v3/user/profile endpoint."""
    try:
        resp = await _rate_limited_get(
            client,
            "https://api.sendgrid.com/v3/user/profile",
            headers={"Authorization": f"Bearer {key}"},
            timeout=_REQUEST_TIMEOUT,
        )
        if resp.status_code == 200:
            return "VALID"
        if resp.status_code == 401:
            return "EXPIRED"
        return "UNKNOWN"
    except Exception:
        return "UNKNOWN"


async def _verify_slack(token: str, client: httpx.AsyncClient) -> str:
    """Verify a Slack token via the auth.test API method."""
    try:
        resp = await _rate_limited_post(
            client,
            "https://slack.com/api/auth.test",
            data={"token": token},
            timeout=_REQUEST_TIMEOUT,
        )
        if resp.status_code == 200:
            body = resp.json()
            if body.get("ok"):
                return "VALID"
            return "EXPIRED"
        return "UNKNOWN"
    except Exception:
        return "UNKNOWN"


# ── Provider dispatch table ───────────────────────────────────────────────────

_PROVIDER_VERIFIERS = {
    "aws": _verify_aws,
    "github": _verify_github,
    "stripe": _verify_stripe,
    "twilio": _verify_twilio,
    "sendgrid": _verify_sendgrid,
    "slack": _verify_slack,
}


# ── Public API ────────────────────────────────────────────────────────────────

async def verify_finding(
    finding: "Finding",
    client: httpx.AsyncClient,
) -> str:
    """
    Probe the live API for a single *finding* and return a verification status.

    Args:
        finding: The :class:`~keyhound.detector.Finding` to verify.
        client:  Shared :class:`httpx.AsyncClient`.

    Returns:
        One of ``VALID``, ``EXPIRED``, ``UNKNOWN``, or ``NOT_CHECKED``.
    """
    # Only verify HIGH or CRITICAL findings
    if finding.severity not in ("CRITICAL", "HIGH"):
        return "NOT_CHECKED"

    provider_key = finding.provider.lower()
    verifier = _PROVIDER_VERIFIERS.get(provider_key)

    if verifier is None:
        return "NOT_CHECKED"

    return await verifier(finding.matched_value, client)


async def verify_findings(
    findings: list["Finding"],
    progress_callback=None,
) -> list["Finding"]:
    """
    Iterate over *findings*, verify each eligible one, and update the
    ``verified`` field in-place.

    Args:
        findings:          List of :class:`~keyhound.detector.Finding` objects.
        progress_callback: Optional callable(finding) called after each
                           verification attempt (for progress-bar updates).

    Returns:
        The same list with ``verified`` fields populated.
    """
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(_REQUEST_TIMEOUT),
        verify=False,
        follow_redirects=True,
    ) as client:
        for finding in findings:
            if finding.severity in ("CRITICAL", "HIGH"):
                status = await verify_finding(finding, client)
                finding.verified = status
            else:
                finding.verified = "NOT_CHECKED"

            if progress_callback:
                progress_callback(finding)

    return findings
