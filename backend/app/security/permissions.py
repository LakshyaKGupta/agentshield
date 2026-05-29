from __future__ import annotations

from ..contracts import Evidence, PermissionManifest


def check_tool_permission(manifest: PermissionManifest, tool_name: str, action: str) -> tuple[bool, Evidence | None]:
    allowed_actions = manifest.tools.get(tool_name)
    if not allowed_actions:
        return False, Evidence(
            source="permission",
            code="POLICY_TOOL_DENIED",
            message=f"Tool '{tool_name}' is not present in the agent permission manifest.",
            confidence=1.0,
        )
    if action not in allowed_actions:
        return False, Evidence(
            source="permission",
            code="POLICY_ACTION_DENIED",
            message=f"Action '{action}' is not allowed for tool '{tool_name}'.",
            confidence=1.0,
        )
    return True, None

