import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

export interface GraphApiResult {
  path: string;
  method: string;
  summary: string;
  description?: string;
  permissions?: {
    delegatedWork?: string[];
    application?: string[];
  };
  resource?: string;
  availability?: string;
  advisories?: unknown[];
}

export interface MsgraphKbSearchResponse {
  query: string;
  totalMatches: number;
  results: GraphApiResult[];
}

/**
 * Lightweight MCP client that connects to the msgraph-kb server via a stdio child process.
 *
 * Configure the server command via environment variables:
 *   MSGRAPH_KB_COMMAND  – executable to run  (e.g. "node")
 *   MSGRAPH_KB_ARGS     – space-separated args (e.g. "/path/to/msgraph-kb/dist/index.js")
 *
 * The client lazily connects on the first call and keeps the connection open.
 * Call close() to clean up the child process when the parent server shuts down.
 */
export class MsgraphKbClient {
  private client: Client | null = null;
  private connected = false;

  private readonly command: string;
  private readonly args: string[];

  constructor() {
    this.command = process.env['MSGRAPH_KB_COMMAND'] ?? '';
    const argsEnv = process.env['MSGRAPH_KB_ARGS'] ?? '';
    this.args = argsEnv ? argsEnv.split(' ').filter(Boolean) : [];
  }

  /** Returns true when the client is configured and can be used. */
  isConfigured(): boolean {
    return this.command.length > 0;
  }

  private async ensureConnected(): Promise<void> {
    if (this.connected) return;

    const transport = new StdioClientTransport({
      command: this.command,
      args: this.args,
      stderr: 'pipe',
    });

    this.client = new Client({ name: 'intunerosetta-hydrator', version: '1.0.0' });
    await this.client.connect(transport);
    this.connected = true;
  }

  /**
   * Call msgraph-kb's search_graph_apis tool.
   */
  async searchGraphApis(query: string, limit = 5): Promise<GraphApiResult[]> {
    await this.ensureConnected();

    const result = await this.client!.callTool({
      name: 'search_graph_apis',
      arguments: { query, limit },
    });

    const textContent = (result.content as Array<{ type: string; text?: string }>)
      .find((c) => c.type === 'text');
    if (!textContent?.text) return [];

    try {
      const parsed = JSON.parse(textContent.text) as MsgraphKbSearchResponse;
      return parsed.results ?? [];
    } catch {
      return [];
    }
  }

  /**
   * Call msgraph-kb's get_api_details tool.
   */
  async getApiDetails(endpoint: string): Promise<GraphApiResult[]> {
    await this.ensureConnected();

    const result = await this.client!.callTool({
      name: 'get_api_details',
      arguments: { endpoint },
    });

    const textContent = (result.content as Array<{ type: string; text?: string }>)
      .find((c) => c.type === 'text');
    if (!textContent?.text) return [];

    try {
      const parsed = JSON.parse(textContent.text) as { matches?: GraphApiResult[] };
      return parsed.matches ?? [];
    } catch {
      return [];
    }
  }

  async close(): Promise<void> {
    if (this.client && this.connected) {
      await this.client.close();
      this.connected = false;
      this.client = null;
    }
  }
}

/** Singleton instance shared across the server lifetime. */
export const msgraphKbClient = new MsgraphKbClient();
