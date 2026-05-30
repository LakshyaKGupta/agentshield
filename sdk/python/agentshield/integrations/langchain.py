from __future__ import annotations

from typing import Any, Dict, List
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.messages import BaseMessage
from agentshield import AgentShield, SecurityBlocked


class AgentShieldLangChainCallback(BaseCallbackHandler):
    """
    AgentShield Callback Handler for LangChain.
    Synchronously enforces prompt injection screening on inbound prompts
    and RBAC checks on outbound tool calls before execution.
    """
    def __init__(self, client: AgentShield, agent_id: str, token: str):
        self.client = client
        self.agent_id = agent_id
        self.token = token

    def on_llm_start(
        self, serialized: Dict[str, Any], prompts: List[str], **kwargs: Any
    ) -> Any:
        """Screener for standard LLM prompt strings."""
        for prompt in prompts:
            self.client.analyze(self.agent_id, self.token, prompt, direction="inbound")

    def on_chat_model_start(
        self, serialized: Dict[str, Any], messages: List[List[BaseMessage]], **kwargs: Any
    ) -> Any:
        """Screener for structured user chat model messages."""
        for message_list in messages:
            for message in message_list:
                if getattr(message, "type", "") == "user":
                    content = str(getattr(message, "content", ""))
                    if content:
                        self.client.analyze(self.agent_id, self.token, content, direction="inbound")

    def on_tool_start(
        self, serialized: Dict[str, Any], input_str: str, **kwargs: Any
    ) -> Any:
        """RBAC gatekeeper for active tool executions."""
        tool_name = serialized.get("name", "unknown_tool")
        # Validate tool permissions dynamically
        self.client.check_tool_call(
            self.agent_id,
            self.token,
            tool_name=tool_name,
            action="execute",
            arguments_hash=None
        )
