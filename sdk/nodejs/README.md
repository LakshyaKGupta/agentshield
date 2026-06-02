# AgentShield Node.js SDK

Production-ready Node.js & TypeScript SDK client for the **AgentShield** real-time AI security middleware.

Provides 100% API parity with the Python client SDK. Integrates zero-dependency native fetch calls under the hood, compatible with Node 18+.

---

## Installation

Because the package is self-hosted locally within this project worktree, you can install it directly into any Node.js project using a local folder reference:

```bash
# In your Node.js application directory:
npm install /path/to/project/sdk/nodejs
```

---

## Quick Start (TypeScript / ES Modules)

```typescript
import { AgentShield, SecurityBlocked } from "agentshield";

async function main() {
  // 1. Instantiate the client from environment variables (reads AGENTSHIELD_API_KEY)
  const shield = AgentShield.from_env();

  // 2. Fetch or dynamically spawn a shielded agent with denial-by-default capabilities
  const agent = await shield.agent("ResearchBot");

  // 3. Screen messages dynamically (e.g. from user input)
  try {
    const verdict = await agent.protect("Explain how to write a quick-start guide.");
    console.log(`🛡️ Message allowed! Trust score: ${verdict.trust_score_after}`);
  } catch (err) {
    if (err instanceof SecurityBlocked) {
      console.warn("🚫 Prompt blocked by AgentShield runtime guard!");
    }
  }

  // 4. Gate tool calls before execution
  try {
    await agent.check_tool("web_search", "read");
    console.log("✅ Tool execution authorized.");
  } catch (err) {
    if (err instanceof SecurityBlocked) {
      console.warn("🚫 Tool call denied by permission manifest!");
    }
  }
}

main().catch(console.error);
```

---

## Quick Start (CommonJS / JavaScript)

```javascript
const { AgentShield, SecurityBlocked } = require("agentshield");

async function run() {
  // Pass credentials directly to constructor
  const shield = new AgentShield("your_workspace_api_key", "http://localhost:8000");

  const agent = await shield.agent("AssistantBot");

  try {
    const verdict = await agent.protect("user input payload");
    console.log("Allowed:", verdict.allowed);
  } catch (err) {
    if (err instanceof SecurityBlocked) {
      console.log("Blocked:", err.message);
    }
  }
}

run().catch(console.error);
```

---

## Full API Reference

The `AgentShield` client exposes all core backend screening and verification REST endpoints:

* **`spawn_agent(name, permissions, metadata)`**: Register a new agent.
* **`list_agents()`**: Retrieve all registered agents in the workspace.
* **`revoke_agent(agentId)`**: Invalidate and disable an agent.
* **`analyze(agentId, token, message, direction, context)`**: Query prompt heuristics.
* **`check_tool_call(agentId, token, toolName, action, argumentsHash)`**: Screen dynamic tool calls.
* **`verify_ledger()`**: Query ledger SHA-256 integrity chain verification.
* **`list_threats()`**: Fetch logged security threat logs.
* **`run_attack_sim(attackType, payload)`**: Execute and test heuristic payloads.
