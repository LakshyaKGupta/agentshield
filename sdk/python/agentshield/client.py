from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
import ssl
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Generator, Optional


class AgentShieldError(RuntimeError):
    pass


class SecurityBlocked(AgentShieldError):
    pass


@dataclass
class ShieldedAgent:
    """A convenience wrapper that binds an agent's identity to the parent shield.

    Obtain one via ``shield.agent("MyBot")`` instead of managing ``agent_id``
    and ``token`` manually.
    """

    agent_id: str
    token: str
    name: str
    _shield: "AgentShield" = field(repr=False)

    # ── Protect a message ────────────────────────────────────────────────────

    def protect(self, message: str, direction: str = "inbound", context: dict[str, Any] | None = None) -> dict[str, Any]:
        """Screen *message* through AgentShield.

        Returns the verdict dict (with ``allowed``, ``trust_score_after``, etc.)
        when the message is allowed.  Raises :class:`SecurityBlocked` when
        AgentShield blocks it.

        Can also be used as a context manager::

            with agent.protect("user prompt"):
                ...  # only reaches here if allowed
        """
        return self._shield.analyze(
            agent_id=self.agent_id,
            token=self.token,
            message=message,
            direction=direction,
            context=context,
        )

    @contextmanager
    def protect_ctx(self, message: str, direction: str = "inbound", context: dict[str, Any] | None = None) -> Generator[dict[str, Any], None, None]:
        """Context-manager form of :meth:`protect`."""
        verdict = self.protect(message, direction=direction, context=context)
        yield verdict

    # ── Gate a tool call ─────────────────────────────────────────────────────

    def check_tool(self, tool_name: str, action: str, arguments_hash: str | None = None) -> dict[str, Any]:
        """Gate a tool call through AgentShield.

        Returns the verdict dict when the call is allowed.  Raises
        :class:`SecurityBlocked` when it is denied.
        """
        return self._shield.check_tool_call(
            agent_id=self.agent_id,
            token=self.token,
            tool_name=tool_name,
            action=action,
            arguments_hash=arguments_hash,
        )


@dataclass
class AgentShield:
    api_key: str
    base_url: str = "http://localhost:8000"
    timeout: float = 10.0

    # ── Constructor helpers ───────────────────────────────────────────────────

    @classmethod
    def from_env(cls) -> "AgentShield":
        """Create an :class:`AgentShield` from environment variables.

        Reads:
        * ``AGENTSHIELD_API_KEY`` (required)
        * ``AGENTSHIELD_BASE_URL`` (optional, defaults to ``http://localhost:8000``)
        """
        api_key = os.environ.get("AGENTSHIELD_API_KEY", "")
        if not api_key:
            raise AgentShieldError(
                "AGENTSHIELD_API_KEY environment variable is not set. "
                "Export it or pass api_key= directly."
            )
        base_url = os.environ.get("AGENTSHIELD_BASE_URL", "http://localhost:8000")
        return cls(api_key=api_key, base_url=base_url)

    # ── High-level agent helper ───────────────────────────────────────────────

    def agent(
        self,
        name: str,
        permissions: dict[str, Any] | None = None,
        agent_type: str = "research_agent",
        metadata: dict[str, Any] | None = None,
    ) -> ShieldedAgent:
        """Create **or** fetch an existing agent by *name*, then return a
        :class:`ShieldedAgent` ready to protect prompts and gate tool calls.

        If an agent with *name* already exists in your workspace the method
        returns a :class:`ShieldedAgent` bound to that agent's credentials.
        Otherwise it registers a new agent and returns the resulting envelope.

        Example::

            shield = AgentShield.from_env()
            agent  = shield.agent("ResearchBot")

            verdict = agent.protect("user prompt here")
            print(f"Allowed: {verdict['allowed']}, Trust: {verdict['trust_score_after']}")

            agent.check_tool("web_search", "read")
        """
        # Try to find an existing agent with this name
        try:
            listing = self.list_agents()
            for a in listing.get("agents", []):
                if a.get("name") == name and a.get("status") == "active":
                    return ShieldedAgent(
                        agent_id=a["agent_id"],
                        token=a["token"],
                        name=name,
                        _shield=self,
                    )
        except AgentShieldError:
            pass  # list call failed — fall through to spawn

        # Spawn a new agent
        effective_permissions = permissions or {
            "tools": {"web_search": ["read"]},
            "default_action": "deny",
        }
        result = self.spawn_agent(name=name, permissions=effective_permissions, metadata=metadata or {})
        return ShieldedAgent(
            agent_id=result["agent_id"],
            token=result["token"],
            name=name,
            _shield=self,
        )

    # ── Internal HTTP helper ──────────────────────────────────────────────────

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None, token: str | None = None) -> dict[str, Any]:
        data = json.dumps(body or {}).encode() if body is not None else None
        headers = {"X-AgentShield-API-Key": self.api_key, "Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(f"{self.base_url}{path}", data=data, headers=headers, method=method)
        try:
            context = None
            if self.base_url.startswith("https://"):
                try:
                    import certifi  # type: ignore
                    context = ssl.create_default_context(cafile=certifi.where())
                except Exception:
                    context = ssl.create_default_context()
            with urllib.request.urlopen(request, timeout=self.timeout, context=context) as response:
                return json.loads(response.read().decode())
        except urllib.error.HTTPError as exc:
            payload = exc.read().decode()
            raise AgentShieldError(payload) from exc

    # ── Existing public API (preserved) ──────────────────────────────────────

    def spawn_agent(self, name: str, permissions: dict[str, Any], metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        return self._request("POST", "/v1/agents", {"name": name, "permissions": permissions, "metadata": metadata or {}})

    def list_agents(self) -> dict[str, Any]:
        return self._request("GET", "/v1/agents")

    def revoke_agent(self, agent_id: str) -> dict[str, Any]:
        return self._request("POST", f"/v1/agents/{agent_id}/revoke")

    def analyze(self, agent_id: str, token: str, message: str, direction: str = "inbound", context: dict[str, Any] | None = None) -> dict[str, Any]:
        verdict = self._request("POST", "/v1/shield/analyze", {"agent_id": agent_id, "message": message, "direction": direction, "context": context or {}}, token)
        if not verdict.get("allowed", False):
            raise SecurityBlocked(verdict.get("reason", "AgentShield blocked the message."))
        return verdict

    def check_tool_call(self, agent_id: str, token: str, tool_name: str, action: str, arguments_hash: str | None = None) -> dict[str, Any]:
        verdict = self._request("POST", "/v1/shield/tool-call", {"agent_id": agent_id, "tool_name": tool_name, "action": action, "arguments_hash": arguments_hash}, token)
        if not verdict.get("allowed", False):
            raise SecurityBlocked(verdict.get("reason", "AgentShield blocked the tool call."))
        return verdict

    def verify_ledger(self) -> dict[str, Any]:
        return self._request("GET", "/v1/ledger/verify")

    def list_threats(self) -> dict[str, Any]:
        return self._request("GET", "/v1/threats")

    def run_attack_sim(self, attack_type: str = "instruction_override", payload: str | None = None) -> dict[str, Any]:
        return self._request("POST", "/v1/attack-sim/run", {"attack_type": attack_type, "payload": payload})
