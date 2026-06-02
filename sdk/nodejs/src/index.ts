export class AgentShieldError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AgentShieldError";
    Object.setPrototypeOf(this, AgentShieldError.prototype);
  }
}

export class SecurityBlocked extends AgentShieldError {
  constructor(message: string) {
    super(message);
    this.name = "SecurityBlocked";
    Object.setPrototypeOf(this, SecurityBlocked.prototype);
  }
}

export class ShieldedAgent {
  public agent_id: string;
  public token: string;
  public name: string;
  private _shield: AgentShield;

  constructor(agent_id: string, token: string, name: string, shield: AgentShield) {
    this.agent_id = agent_id;
    this.token = token;
    this.name = name;
    this._shield = shield;
  }

  /**
   * Screen message through AgentShield.
   * Throws SecurityBlocked error if the message is blocked.
   * Returns the API verdict payload on success.
   */
  public async protect(
    message: string,
    direction: string = "inbound",
    context: Record<string, any> | null = null
  ): Promise<Record<string, any>> {
    return this._shield.analyze(this.agent_id, this.token, message, direction, context);
  }

  /**
   * Gate a tool call through AgentShield.
   * Throws SecurityBlocked error if the tool call is blocked.
   * Returns the API verdict payload on success.
   */
  public async check_tool(
    tool_name: string,
    action: string,
    arguments_hash: string | null = null
  ): Promise<Record<string, any>> {
    return this._shield.check_tool_call(this.agent_id, this.token, tool_name, action, arguments_hash);
  }
}

export class AgentShield {
  public api_key: string;
  public base_url: string;
  public timeout: number;

  constructor(api_key: string, base_url: string = "http://localhost:8000", timeout: number = 10.0) {
    this.api_key = api_key;
    // Strip trailing slash if present
    this.base_url = base_url.replace(/\/+$/, "");
    // Convert timeout seconds to milliseconds
    this.timeout = timeout * 1000;
  }

  /**
   * Instantiate an AgentShield client from environment variables.
   * Reads:
   * - AGENTSHIELD_API_KEY (required)
   * - AGENTSHIELD_BASE_URL (optional, defaults to http://localhost:8000)
   */
  public static from_env(): AgentShield {
    const apiKey = typeof process !== "undefined" ? process.env.AGENTSHIELD_API_KEY : "";
    if (!apiKey) {
      throw new AgentShieldError(
        "AGENTSHIELD_API_KEY environment variable is not set. Export it or pass api_key directly."
      );
    }
    const baseUrl = (typeof process !== "undefined" && process.env.AGENTSHIELD_BASE_URL) || "http://localhost:8000";
    return new AgentShield(apiKey, baseUrl);
  }

  /**
   * Create or fetch an existing agent by name, returning a ShieldedAgent
   * ready to screen messages and gate tool calls.
   */
  public async agent(
    name: string,
    permissions: Record<string, any> | null = null,
    agent_type: string = "research_agent",
    metadata: Record<string, any> | null = null
  ): Promise<ShieldedAgent> {
    try {
      const listing = await this.list_agents();
      if (listing && Array.isArray(listing.agents)) {
        for (const a of listing.agents) {
          if (a.name === name && a.status === "active") {
            return new ShieldedAgent(a.agent_id, a.token, name, this);
          }
        }
      }
    } catch (err) {
      // Fall through to register if list fails
    }

    const effectivePermissions = permissions || {
      tools: { web_search: ["read"] },
      default_action: "deny",
    };

    const result = await this.spawn_agent(name, effectivePermissions, metadata);
    return new ShieldedAgent(result.agent_id, result.token, name, this);
  }

  /**
   * Unified Node fetch helper.
   */
  private async _request(
    method: string,
    path: string,
    body: Record<string, any> | null = null,
    token: string | null = null
  ): Promise<Record<string, any>> {
    const headers: Record<string, string> = {
      "X-AgentShield-API-Key": this.api_key,
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    const abortController = new AbortController();
    const timeoutTimer = setTimeout(() => abortController.abort(), this.timeout);

    try {
      const res = await fetch(`${this.base_url}${path}`, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        signal: abortController.signal,
      });

      if (!res.ok) {
        let errMsg = `HTTP ${res.status}`;
        try {
          const errPayload = await res.json() as any;
          errMsg = errPayload?.error?.message || errPayload?.detail || errMsg;
        } catch {
          errMsg = (await res.text()) || errMsg;
        }
        throw new AgentShieldError(errMsg);
      }

      return (await res.json()) as Record<string, any>;
    } catch (err: any) {
      if (err instanceof DOMException && err.name === "AbortError") {
        throw new AgentShieldError("AgentShield API request timed out.");
      }
      if (err instanceof AgentShieldError) {
        throw err;
      }
      throw new AgentShieldError(err.message || String(err));
    } finally {
      clearTimeout(timeoutTimer);
    }
  }

  // ── SDK Methods ───────────────────────────────────────────────────────────

  public async spawn_agent(
    name: string,
    permissions: Record<string, any>,
    metadata: Record<string, any> | null = null
  ): Promise<Record<string, any>> {
    return this._request("POST", "/v1/agents", {
      name,
      permissions,
      metadata: metadata || {},
    });
  }

  public async list_agents(): Promise<Record<string, any>> {
    return this._request("GET", "/v1/agents");
  }

  public async revoke_agent(agent_id: string): Promise<Record<string, any>> {
    return this._request("POST", `/v1/agents/${agent_id}/revoke`);
  }

  public async analyze(
    agent_id: string,
    token: string,
    message: string,
    direction: string = "inbound",
    context: Record<string, any> | null = null
  ): Promise<Record<string, any>> {
    const verdict = await this._request(
      "POST",
      "/v1/shield/analyze",
      {
        agent_id,
        message,
        direction,
        context: context || {},
      },
      token
    );
    if (!verdict.allowed) {
      throw new SecurityBlocked(verdict.reason || "AgentShield blocked the message.");
    }
    return verdict;
  }

  public async check_tool_call(
    agent_id: string,
    token: string,
    tool_name: string,
    action: string,
    arguments_hash: string | null = null
  ): Promise<Record<string, any>> {
    const verdict = await this._request(
      "POST",
      "/v1/shield/tool-call",
      {
        agent_id,
        tool_name,
        action,
        arguments_hash,
      },
      token
    );
    if (!verdict.allowed) {
      throw new SecurityBlocked(verdict.reason || "AgentShield blocked the tool call.");
    }
    return verdict;
  }

  public async verify_ledger(): Promise<Record<string, any>> {
    return this._request("GET", "/v1/ledger/verify");
  }

  public async list_threats(): Promise<Record<string, any>> {
    return this._request("GET", "/v1/threats");
  }

  public async run_attack_sim(
    attack_type: string = "instruction_override",
    payload: string | null = null
  ): Promise<Record<string, any>> {
    return this._request("POST", "/v1/attack-sim/run", {
      attack_type,
      payload,
    });
  }
}
