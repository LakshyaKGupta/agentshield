#!/usr/bin/env python3
"""
AgentShield - Interactive "Gemini" AI Agent Simulator
────────────────────────────────────────────────────────
This script runs a conversational AI agent (simulating a Google Gemini security agent)
that is fully protected by the AgentShield runtime security middleware.

For every message you enter:
1. The script screens the prompt through AgentShield (`agent.protect`).
2. If the prompt is BLOCKED, a threat event is registered in the ledger, and the LLM is never called.
3. If ALLOWED, it forwards the query to the generative model (Llama/Groq or local fallback) to answer.
4. If the agent triggers a tool (e.g. searching the web), it checks permissions with AgentShield (`agent.check_tool`).

All actions, trust score decays, blocked threats, and ledger chains are reflected
in real-time inside your AgentShield Web Console (http://localhost:5173)!
"""

import os
import sys
import json
import requests
from agentshield import AgentShield, SecurityBlocked

def main():
    print("=" * 70)
    print("🛡️  AgentShield - Interactive 'Gemini' AI Agent Shielding Demo  🛡️")
    print("=" * 70)

    # 1. Resolve credentials and connect to the local AgentShield backend
    api_key = os.environ.get("AGENTSHIELD_API_KEY")
    if not api_key:
        print("🔑 No AGENTSHIELD_API_KEY found. Attempting auto-login to demo workspace...")
        email = "agent-demo-developer@example.com"
        password = "securepassword123"
        try:
            r = requests.post(
                "http://127.0.0.1:8000/v1/auth/login",
                json={"email": email, "password": password}
            )
            if r.status_code == 200:
                api_key = r.json()["api_key"]
                print(f"✅ Auto-login successful! API Key: {api_key}\n")
            else:
                # Try signup if login failed
                r = requests.post(
                    "http://127.0.0.1:8000/v1/auth/signup",
                    json={"email": email, "password": password, "workspace_name": "Demo Developer Workspace"}
                )
                if r.status_code == 200:
                    api_key = r.json()["api_key"]
                    print(f"✅ Workspace signed up! API Key: {api_key}\n")
                else:
                    print(f"❌ Failed to obtain API key: {r.text}")
                    sys.exit(1)
        except Exception as exc:
            print(f"❌ Connection to local backend failed: {exc}")
            print("Please ensure uvicorn is running on http://127.0.0.1:8000.")
            sys.exit(1)

    # 2. Instantiate AgentShield client
    shield = AgentShield(api_key=api_key, base_url="http://localhost:8000")

    # 3. Spawn a brand new agent identity in the workspace registry
    agent_name = "GeminiSecurityAgent"
    print(f"🤖 Registering active shielded agent '{agent_name}' in console vault...")
    agent = shield.agent(agent_name, permissions={
        "tools": {
            "web_search": ["read"],
            "send_email": ["deny"]  # Blocked tool
        },
        "default_action": "deny"
    })
    print(f"✅ Shielded Agent Bound!")
    print(f"   Agent ID: {agent.agent_id}")
    print(f"   Token (RS256 JWT): {agent.token[:30]}...\n")
    print("⚡ Open your Web Console at http://localhost:5173 to watch events dynamically!")
    print("=" * 70)
    print("Chat active. Type your prompts below. Type 'exit' to quit.\n")

    while True:
        try:
            user_msg = input("\033[1;34mYou:\033[0m ")
            if not user_msg.strip():
                continue
            if user_msg.lower().strip() == "exit":
                print("👋 Exiting interactive chat session.")
                break

            # ── STEP 1: Screen the prompt through AgentShield before LLM is called ──
            print("   \033[2m[AgentShield] Screening inbound prompt...\033[0m")
            try:
                verdict = agent.protect(user_msg)
                print(f"   \033[92m[AgentShield] ALLOWED (Trust: {verdict.get('trust_score_after')}) - Routing to LLM...\033[0m")
                
                # ── STEP 2: Trigger tool if user requests it (Simulated Agent Tool Gating) ──
                if "search" in user_msg.lower() or "find" in user_msg.lower():
                    print("   \033[2m[Agent] Agent attempting tool execution 'web_search:read'...\033[0m")
                    tool_verdict = agent.check_tool("web_search", "read")
                    print("   \033[92m[AgentShield] Tool call 'web_search:read' ALLOWED by Permission Manifest!\033[0m")

                if "email" in user_msg.lower() or "send" in user_msg.lower():
                    print("   \033[2m[Agent] Agent attempting tool execution 'send_email:write'...\033[0m")
                    # This tool is denied by default in the manifest
                    tool_verdict = agent.check_tool("send_email", "write")

                # ── STEP 3: Forward the clean prompt to the Generative LLM backend ──
                chat_res = requests.post(
                    "http://127.0.0.1:8000/v1/chat",
                    json={"message": user_msg, "api_key": api_key}
                )
                if chat_res.status_code == 200:
                    reply = chat_res.json().get("reply") or "No response from model."
                    print(f"\033[1;32m{agent_name}:\033[0m {reply}\n")
                else:
                    print(f"\033[1;31m[LLM Error]:\033[0m {chat_res.status_code} - {chat_res.text}\n")

            except SecurityBlocked as exc:
                # ── STEP 4: Prompt was blocked! Prevent LLM calling and alert ──
                print(f"   \033[91m[AgentShield] BLOCKED by security heuristic guards!\033[0m")
                print(f"   \033[91mReason: {exc}\033[0m")
                print(f"   \033[2mTelemetry: Threat logged in ledger. Check http://localhost:5173/threats\033[0m\n")

        except KeyboardInterrupt:
            print("\n👋 Exiting interactive chat session.")
            break
        except Exception as exc:
            print(f"\n❌ Error during execution: {exc}\n")

if __name__ == "__main__":
    main()
