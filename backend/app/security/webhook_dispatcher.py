import hashlib
import hmac
import json
import logging
import httpx

logger = logging.getLogger(__name__)


def dispatch_security_webhook(webhook_url: str, webhook_secret: str, payload: dict) -> None:
    """Send an asynchronous webhook POST request to the configured URL with HMAC-SHA256 signature."""
    try:
        # Construct exact JSON string
        payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')

        # Calculate HMAC-SHA256 signature
        signature = hmac.new(
            webhook_secret.encode('utf-8'),
            payload_bytes,
            hashlib.sha256
        ).hexdigest()

        headers = {
            "Content-Type": "application/json",
            "X-AgentShield-Signature": signature,
            "User-Agent": "AgentShield-Webhook-Dispatcher/0.1.0"
        }

        # Send HTTP POST
        logger.info(f"Dispatching security webhook to {webhook_url}...")
        with httpx.Client(timeout=8.0) as client:
            response = client.post(webhook_url, content=payload_bytes, headers=headers)
            if response.status_code >= 400:
                logger.warning(
                    f"Webhook dispatch to {webhook_url} failed with status {response.status_code}: {response.text}"
                )
            else:
                logger.info(f"Webhook successfully dispatched to {webhook_url} (status {response.status_code})")
    except Exception as e:
        logger.error(f"Failed to dispatch security webhook to {webhook_url}: {e}", exc_info=True)
