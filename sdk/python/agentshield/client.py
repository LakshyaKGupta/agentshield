from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


class AgentShieldError(RuntimeError):
    pass


class SecurityBlocked(AgentShieldError):
    pass


@dataclass
class AgentShield:
    api_key: str
    base_url: str = "http://localhost:8000"
    timeout: float = 10.0

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None, token: str | None = None) -> dict[str, Any]:
        data = json.dumps(body or {}).encode() if body is not None else None
        headers = {"X-AgentShield-API-Key": self.api_key, "Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(f"{self.base_url}{path}", data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode())
        except urllib.error.HTTPError as exc:
            payload = exc.read().decode()
            raise AgentShieldError(payload) from exc

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
