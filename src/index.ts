#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { seedDatabase, searchPolicies, findByCspPathFragment } from './db';
import { translateKey, normalizeKey, splitValueSegment, buildMetadata } from './parser';
import { PolicyMetadata } from './types';
import { msgraphKbClient } from './msgraph-client';
import { hydrateFromMsgraphKb, hydratePolicyRecord } from './hydrator';

// ─── Bootstrap ────────────────────────────────────────────────────────────────
seedDatabase();

// ─── MCP Server ───────────────────────────────────────────────────────────────
const server = new McpServer({
  name: 'IntuneRosetta',
  version: '1.0.0',
});

// ── Tool: translate_csp_key ──────────────────────────────────────────────────
server.tool(
  'translate_csp_key',
  'Translates a raw underscore-delimited OMA-URI / CSP path string into structured, human-readable policy metadata. When the key is not in the local database and msgraph-kb is configured, automatically enriches it via msgraph-kb before returning.',
  {
    key: z.string().describe('Raw underscore-delimited CSP/OMA-URI string, e.g. device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts_2'),
  },
  async ({ key }) => {
    // Try msgraph-kb enrichment for unknown keys before falling back to best-effort
    await hydrateFromMsgraphKb(msgraphKbClient, key);

    const metadata = translateKey(key);
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(metadata, null, 2),
        },
      ],
    };
  }
);

// ── Tool: batch_translate ────────────────────────────────────────────────────
server.tool(
  'batch_translate',
  'Translates an array of raw underscore-delimited OMA-URI / CSP path strings into structured policy metadata.',
  {
    keys: z.array(z.string()).describe('Array of raw underscore-delimited CSP/OMA-URI strings to translate'),
  },
  async ({ keys }) => {
    // Enrich any unknown keys via msgraph-kb in parallel (fire-and-forget errors)
    await Promise.allSettled(keys.map((k) => hydrateFromMsgraphKb(msgraphKbClient, k)));

    const results: PolicyMetadata[] = keys.map((k) => translateKey(k));
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(results, null, 2),
        },
      ],
    };
  }
);

// ── Tool: search_policy ──────────────────────────────────────────────────────
server.tool(
  'search_policy',
  'Performs a fuzzy keyword search across the internal policy database by name, description, category, or CSP path fragment.',
  {
    query: z.string().describe('Keyword or phrase to search for, e.g. "obfuscated scripts", "bitlocker", "laps password"'),
    limit: z.number().int().min(1).max(100).optional().default(20).describe('Maximum number of results to return (default 20)'),
  },
  async ({ query, limit }) => {
    const records = searchPolicies(query, limit);
    const results = records.map((r) => {
      const { valueSegment } = splitValueSegment(r.normalized_key);
      return buildMetadata(r, valueSegment);
    });
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(results, null, 2),
        },
      ],
    };
  }
);

// ── Tool: resolve_to_csp ─────────────────────────────────────────────────────
server.tool(
  'resolve_to_csp',
  'Resolves a human-readable policy name or keyword to matching CSP key(s) and full metadata. Supports partial/fuzzy matching so inputs like "block obfuscated scripts" or "bitlocker startup auth" resolve correctly.',
  {
    query: z.string().describe('Human-readable policy name or keyword, e.g. "block obfuscated scripts", "bitlocker startup authentication", "laps password length"'),
    limit: z.number().int().min(1).max(100).optional().default(10).describe('Maximum number of results to return (default 10)'),
  },
  async ({ query, limit }) => {
    // Combine name/description search with CSP path fragment search and deduplicate
    const nameResults = searchPolicies(query, limit);
    const cspResults = findByCspPathFragment(normalizeKey(query), limit);

    const seen = new Set<string>();
    const combined = [...nameResults, ...cspResults].filter((r) => {
      if (seen.has(r.normalized_key)) return false;
      seen.add(r.normalized_key);
      return true;
    }).slice(0, limit);

    const results = combined.map((r) => ({
      csp_key: r.normalized_key,
      ...buildMetadata(r, undefined),
    }));

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(results, null, 2),
        },
      ],
    };
  }
);

// ── Tool: hydrate_db ─────────────────────────────────────────────────────────
server.tool(
  'hydrate_db',
  'Stores one or more policy metadata records directly into the local SQLite database. Use this to persist data fetched from msgraph-kb or other MCP sources so that future lookups are served from the local cache. The LLM workflow: call msgraph-kb (search_graph_apis / get_api_details), then call this tool with the results.',
  {
    policies: z.array(
      z.object({
        csp_key: z.string().describe('Normalised underscore-delimited CSP key (device_vendor_msft_ prefix is stripped automatically)'),
        name: z.string().describe('Human-readable policy name'),
        description: z.string().optional().default('').describe('What the setting does'),
        csp_path: z.string().describe('Canonical OMA-URI path, e.g. ./Device/Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules'),
        category: z.string().optional().default('').describe('Policy area, e.g. "Defender ASR", "BitLocker", "LAPS"'),
        docs_url: z.string().optional().default('').describe('Link to Microsoft documentation'),
        value_map: z.record(z.string(), z.string()).optional().default({}).describe('Map of raw values to human-readable labels, e.g. {"0":"Disabled","1":"Block","2":"Audit"}'),
      })
    ).min(1).describe('One or more policy records to store'),
  },
  async ({ policies }) => {
    let stored = 0;
    for (const p of policies) {
      hydratePolicyRecord({
        normalized_key: normalizeKey(p.csp_key),
        name: p.name,
        description: p.description,
        csp_path: p.csp_path,
        category: p.category,
        docs_url: p.docs_url,
        value_map: JSON.stringify(p.value_map),
      });
      stored++;
    }
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({ stored, message: `Successfully stored ${stored} policy record(s) in the database.` }, null, 2),
        },
      ],
    };
  }
);

// ── Tool: enrich_policy ──────────────────────────────────────────────────────
server.tool(
  'enrich_policy',
  'Looks up a CSP key in msgraph-kb and caches the enriched metadata in the local database. Requires MSGRAPH_KB_COMMAND to be set. Returns the enriched metadata if found, or a message indicating the key was already known or msgraph-kb is not configured.',
  {
    key: z.string().describe('Raw underscore-delimited CSP/OMA-URI string to enrich from msgraph-kb'),
  },
  async ({ key }) => {
    if (!msgraphKbClient.isConfigured()) {
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              enriched: false,
              message: 'msgraph-kb is not configured. Set MSGRAPH_KB_COMMAND (and optionally MSGRAPH_KB_ARGS) environment variables to enable auto-enrichment from msgraph-kb.',
            }, null, 2),
          },
        ],
      };
    }

    const record = await hydrateFromMsgraphKb(msgraphKbClient, key);
    if (!record) {
      // Either already in DB or no results from msgraph-kb
      const existing = translateKey(key);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              enriched: false,
              message: 'Key was already in the local database or msgraph-kb returned no results.',
              metadata: existing,
            }, null, 2),
          },
        ],
      };
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            enriched: true,
            message: 'Policy enriched from msgraph-kb and cached in the local database.',
            metadata: translateKey(key),
          }, null, 2),
        },
      ],
    };
  }
);

// ─── Cleanup on shutdown ──────────────────────────────────────────────────────
process.on('SIGINT', () => { msgraphKbClient.close().finally(() => process.exit(0)); });
process.on('SIGTERM', () => { msgraphKbClient.close().finally(() => process.exit(0)); });

// ─── Start ────────────────────────────────────────────────────────────────────
async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Log to stderr so it doesn't interfere with the MCP stdio protocol
  process.stderr.write('IntuneRosetta MCP server started\n');
  if (msgraphKbClient.isConfigured()) {
    process.stderr.write(`msgraph-kb enrichment enabled (MSGRAPH_KB_COMMAND=${process.env['MSGRAPH_KB_COMMAND']})\n`);
  }
}

main().catch((err) => {
  process.stderr.write(`Fatal error: ${err}\n`);
  process.exit(1);
});

