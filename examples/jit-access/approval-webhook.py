#!/usr/bin/env python3
"""approval-webhook.py — Webhook endpoint for Vault control group approvals.

Receives Vault control group authorization requests, sends notifications
(Slack/email), accepts or denies based on policy or manual review, and
logs all decisions with full audit trail.

Environment variables:
    WEBHOOK_PORT        - Listen port (default: 8200)
    WEBHOOK_HOST        - Listen host (default: 0.0.0.0)
    VAULT_ADDR          - Vault server URL (required)
    VAULT_TOKEN         - Vault token with approver policy (required)
    SLACK_WEBHOOK_URL   - Slack incoming webhook for notifications (optional)
    SMTP_HOST           - SMTP server for email notifications (optional)
    SMTP_PORT           - SMTP port (default: 587)
    SMTP_FROM           - Sender email address (optional)
    SMTP_TO             - Recipient email address(es), comma-separated (optional)
    AUTO_APPROVE_SCOPES - Comma-separated scopes to auto-approve (optional)
    LOG_FILE            - Audit log file path (default: /var/log/jit-approvals.json)

Usage:
    python3 approval-webhook.py
    WEBHOOK_PORT=9090 python3 approval-webhook.py
"""

import datetime
import hashlib
import hmac
import json
import logging
import os
import smtplib
import sys
import urllib.request
import urllib.error
from email.mime.text import MIMEText
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

WEBHOOK_PORT = int(os.environ.get("WEBHOOK_PORT", "8200"))
WEBHOOK_HOST = os.environ.get("WEBHOOK_HOST", "0.0.0.0")
VAULT_ADDR = os.environ.get("VAULT_ADDR", "")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_FROM = os.environ.get("SMTP_FROM", "")
SMTP_TO = os.environ.get("SMTP_TO", "")
AUTO_APPROVE_SCOPES = [
    s.strip()
    for s in os.environ.get("AUTO_APPROVE_SCOPES", "").split(",")
    if s.strip()
]
LOG_FILE = os.environ.get("LOG_FILE", "/var/log/jit-approvals.json")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("jit-approval-webhook")

# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------


def audit_log(entry: dict[str, Any]) -> None:
    """Append a structured JSON audit entry to the log file."""
    entry["logged_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    line = json.dumps(entry, default=str)
    log.info("AUDIT: %s", line)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except OSError as exc:
        log.warning("Could not write audit log to %s: %s", LOG_FILE, exc)


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------


def notify_slack(payload: dict[str, Any]) -> bool:
    """Send a Slack notification for a control group request."""
    if not SLACK_WEBHOOK_URL:
        log.debug("Slack not configured, skipping notification")
        return False

    is_break_glass = payload.get("break_glass", False)
    severity = ":rotating_light: BREAK-GLASS" if is_break_glass else ":key: JIT Request"

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{severity} — Privileged Access Request",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Requester:*\n{payload.get('requester', 'unknown')}"},
                {"type": "mrkdwn", "text": f"*Scope:*\n{payload.get('scope', 'unknown')}"},
                {"type": "mrkdwn", "text": f"*Duration:*\n{payload.get('duration', 'unknown')}"},
                {"type": "mrkdwn", "text": f"*Accessor:*\n`{payload.get('accessor', 'unknown')}`"},
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Reason:*\n> {payload.get('reason', 'No reason provided')}",
            },
        },
    ]

    if not is_break_glass:
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Approve"},
                        "style": "primary",
                        "action_id": "jit_approve",
                        "value": payload.get("accessor", ""),
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Deny"},
                        "style": "danger",
                        "action_id": "jit_deny",
                        "value": payload.get("accessor", ""),
                    },
                ],
            }
        )

    slack_payload = json.dumps({"blocks": blocks}).encode("utf-8")
    req = urllib.request.Request(
        SLACK_WEBHOOK_URL,
        data=slack_payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=10)
        return True
    except urllib.error.URLError as exc:
        log.warning("Slack notification failed: %s", exc)
        return False


def notify_email(payload: dict[str, Any]) -> bool:
    """Send an email notification for a control group request."""
    if not all([SMTP_HOST, SMTP_FROM, SMTP_TO]):
        log.debug("Email not configured, skipping notification")
        return False

    is_break_glass = payload.get("break_glass", False)
    subject_prefix = "[BREAK-GLASS]" if is_break_glass else "[JIT Request]"

    body = (
        f"Privileged Access Request\n"
        f"{'=' * 40}\n\n"
        f"Requester: {payload.get('requester', 'unknown')}\n"
        f"Scope:     {payload.get('scope', 'unknown')}\n"
        f"Duration:  {payload.get('duration', 'unknown')}\n"
        f"Reason:    {payload.get('reason', 'No reason provided')}\n"
        f"Accessor:  {payload.get('accessor', 'unknown')}\n"
        f"Timestamp: {payload.get('timestamp', 'unknown')}\n\n"
    )

    if not is_break_glass:
        body += (
            f"To approve:\n"
            f"  curl -X POST {WEBHOOK_HOST}:{WEBHOOK_PORT}/approve "
            f"-d '{{\"accessor\": \"{payload.get('accessor', '')}\", "
            f"\"decision\": \"approve\"}}'\n\n"
            f"To deny:\n"
            f"  curl -X POST {WEBHOOK_HOST}:{WEBHOOK_PORT}/approve "
            f"-d '{{\"accessor\": \"{payload.get('accessor', '')}\", "
            f"\"decision\": \"deny\"}}'\n"
        )
    else:
        body += "BREAK-GLASS: Access was granted immediately. Post-incident review required.\n"

    msg = MIMEText(body)
    msg["Subject"] = f"{subject_prefix} {payload.get('requester', 'unknown')} — {payload.get('scope', 'unknown')}"
    msg["From"] = SMTP_FROM
    msg["To"] = SMTP_TO

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.sendmail(SMTP_FROM, SMTP_TO.split(","), msg.as_string())
        return True
    except Exception as exc:
        log.warning("Email notification failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Vault control group operations
# ---------------------------------------------------------------------------


def vault_api(method: str, path: str, data: dict | None = None) -> dict:
    """Make a Vault API request."""
    url = f"{VAULT_ADDR}/v1/{path}"
    body = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "X-Vault-Token": VAULT_TOKEN,
            "Content-Type": "application/json",
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8") if exc.fp else ""
        log.error("Vault API error %s %s: %s %s", method, path, exc.code, error_body)
        raise
    except urllib.error.URLError as exc:
        log.error("Vault API connection error %s %s: %s", method, path, exc)
        raise


def approve_control_group(accessor: str) -> dict:
    """Authorize a pending control group request in Vault."""
    return vault_api("POST", "sys/control-group/authorize", {"accessor": accessor})


def check_control_group(accessor: str) -> dict:
    """Check the status of a control group request."""
    return vault_api("POST", "sys/control-group/request", {"accessor": accessor})


# ---------------------------------------------------------------------------
# Policy evaluation
# ---------------------------------------------------------------------------


def evaluate_policy(payload: dict[str, Any]) -> str:
    """Evaluate whether a request should be auto-approved, auto-denied, or held.

    Returns: "approve", "deny", or "pending" (requires manual review).
    """
    scope = payload.get("scope", "")
    requester = payload.get("requester", "")

    # Break-glass requests are already granted — just log and notify
    if payload.get("break_glass"):
        return "approve"

    # Auto-approve configured scopes (e.g., low-risk staging access)
    if scope in AUTO_APPROVE_SCOPES:
        log.info("Auto-approving scope %s per AUTO_APPROVE_SCOPES policy", scope)
        return "approve"

    # Block requests with empty or suspicious reasons
    reason = payload.get("reason", "")
    if len(reason) < 10:
        log.warning("Denying request with insufficient reason: %r", reason)
        return "deny"

    # All other requests require manual review
    return "pending"


# ---------------------------------------------------------------------------
# Request signature verification
# ---------------------------------------------------------------------------


def verify_signature(body: bytes, signature: str) -> bool:
    """Verify HMAC-SHA256 signature if WEBHOOK_SECRET is configured."""
    if not WEBHOOK_SECRET:
        return True  # No secret configured, skip verification
    expected = hmac.new(
        WEBHOOK_SECRET.encode("utf-8"), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------


class ApprovalHandler(BaseHTTPRequestHandler):
    """HTTP request handler for JIT approval webhook."""

    def log_message(self, format: str, *args: Any) -> None:
        """Route HTTP logs through the application logger."""
        log.info("HTTP %s", format % args)

    def _send_json(self, status: int, data: dict) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def do_GET(self) -> None:
        """Health check endpoint."""
        if self.path == "/health":
            self._send_json(200, {"status": "healthy", "service": "jit-approval-webhook"})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        """Handle incoming requests."""
        body = self._read_body()

        # Verify signature if configured
        sig = self.headers.get("X-Webhook-Signature", "")
        if not verify_signature(body, sig):
            log.warning("Invalid webhook signature from %s", self.client_address)
            self._send_json(403, {"error": "invalid signature"})
            return

        try:
            payload = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self._send_json(400, {"error": "invalid JSON"})
            return

        if self.path == "/request":
            self._handle_request(payload)
        elif self.path == "/approve":
            self._handle_approval(payload)
        elif self.path == "/status":
            self._handle_status(payload)
        elif self.path == "/break-glass":
            self._handle_break_glass(payload)
        else:
            self._send_json(404, {"error": "not found"})

    def _handle_request(self, payload: dict) -> None:
        """Handle a new control group request notification from Vault."""
        accessor = payload.get("accessor", "")
        requester = payload.get("requester", "unknown")
        scope = payload.get("scope", "unknown")
        reason = payload.get("reason", "")
        duration = payload.get("duration", "unknown")

        audit_log({
            "event": "elevation_requested",
            "accessor": accessor,
            "requester": requester,
            "scope": scope,
            "reason": reason,
            "duration": duration,
            "source_ip": self.client_address[0],
        })

        # Evaluate against auto-approval policy
        decision = evaluate_policy(payload)

        if decision == "approve":
            try:
                result = approve_control_group(accessor)
                audit_log({
                    "event": "elevation_auto_approved",
                    "accessor": accessor,
                    "requester": requester,
                    "scope": scope,
                    "reason": reason,
                    "policy": "auto-approve",
                })
                notify_slack(payload)
                notify_email(payload)
                self._send_json(200, {"status": "approved", "accessor": accessor})
            except Exception as exc:
                log.error("Failed to auto-approve %s: %s", accessor, exc)
                self._send_json(500, {"error": "approval failed", "detail": str(exc)})
            return

        if decision == "deny":
            audit_log({
                "event": "elevation_auto_denied",
                "accessor": accessor,
                "requester": requester,
                "scope": scope,
                "reason": reason,
                "policy": "auto-deny",
            })
            self._send_json(200, {"status": "denied", "accessor": accessor, "reason": "policy"})
            return

        # Pending — notify approvers for manual review
        notify_slack(payload)
        notify_email(payload)
        audit_log({
            "event": "elevation_pending_review",
            "accessor": accessor,
            "requester": requester,
            "scope": scope,
            "reason": reason,
        })
        self._send_json(202, {"status": "pending", "accessor": accessor})

    def _handle_approval(self, payload: dict) -> None:
        """Handle a manual approval/denial decision."""
        accessor = payload.get("accessor", "")
        decision = payload.get("decision", "")
        approver = payload.get("approver", self.client_address[0])
        comment = payload.get("comment", "")

        if not accessor:
            self._send_json(400, {"error": "accessor is required"})
            return

        if decision not in ("approve", "deny"):
            self._send_json(400, {"error": "decision must be 'approve' or 'deny'"})
            return

        if decision == "approve":
            try:
                result = approve_control_group(accessor)
                audit_log({
                    "event": "elevation_approved",
                    "accessor": accessor,
                    "approver": approver,
                    "comment": comment,
                    "decision": "approve",
                })
                self._send_json(200, {"status": "approved", "accessor": accessor})
            except Exception as exc:
                log.error("Vault approval failed for %s: %s", accessor, exc)
                self._send_json(500, {"error": "vault approval failed", "detail": str(exc)})
        else:
            audit_log({
                "event": "elevation_denied",
                "accessor": accessor,
                "approver": approver,
                "comment": comment,
                "decision": "deny",
            })
            self._send_json(200, {"status": "denied", "accessor": accessor})

    def _handle_status(self, payload: dict) -> None:
        """Check the status of a control group request."""
        accessor = payload.get("accessor", "")
        if not accessor:
            self._send_json(400, {"error": "accessor is required"})
            return

        try:
            result = check_control_group(accessor)
            self._send_json(200, result)
        except Exception as exc:
            self._send_json(500, {"error": "status check failed", "detail": str(exc)})

    def _handle_break_glass(self, payload: dict) -> None:
        """Handle break-glass notification (access already granted, audit-only)."""
        accessor = payload.get("accessor", "")
        requester = payload.get("requester", "unknown")
        scope = payload.get("scope", "unknown")
        reason = payload.get("reason", "")

        audit_log({
            "event": "break_glass_activated",
            "accessor": accessor,
            "requester": requester,
            "scope": scope,
            "reason": reason,
            "severity": "critical",
            "action_required": "post-incident review within 24 hours",
            "source_ip": self.client_address[0],
        })

        payload["break_glass"] = True
        notify_slack(payload)
        notify_email(payload)

        self._send_json(200, {
            "status": "acknowledged",
            "accessor": accessor,
            "message": "Break-glass logged. Post-incident review required.",
        })


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    if not VAULT_ADDR:
        log.error("VAULT_ADDR is required")
        sys.exit(1)
    if not VAULT_TOKEN:
        log.error("VAULT_TOKEN is required (must have approver policy)")
        sys.exit(1)

    server = HTTPServer((WEBHOOK_HOST, WEBHOOK_PORT), ApprovalHandler)
    log.info(
        "JIT approval webhook listening on %s:%d",
        WEBHOOK_HOST,
        WEBHOOK_PORT,
    )
    log.info("Endpoints: /request, /approve, /status, /break-glass, /health")
    log.info("Audit log: %s", LOG_FILE)
    if AUTO_APPROVE_SCOPES:
        log.info("Auto-approve scopes: %s", ", ".join(AUTO_APPROVE_SCOPES))

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
