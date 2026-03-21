#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { seedDatabase, searchPolicies, findByCspPathFragment } from './db';
import { translateKey, normalizeKey, splitValueSegment, buildMetadata } from './parser';
import { PolicyMetadata } from './types';

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
  'Translates a raw underscore-delimited OMA-URI / CSP path string into structured, human-readable policy metadata.',
  {
    key: z.string().describe('Raw underscore-delimited CSP/OMA-URI string, e.g. device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts_2'),
  },
  async ({ key }) => {
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

// ─── Start ────────────────────────────────────────────────────────────────────
async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Log to stderr so it doesn't interfere with the MCP stdio protocol
  process.stderr.write('IntuneRosetta MCP server started\n');
}

main().catch((err) => {
  process.stderr.write(`Fatal error: ${err}\n`);
  process.exit(1);
});
