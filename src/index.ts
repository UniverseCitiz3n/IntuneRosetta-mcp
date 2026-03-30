#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { seedDatabase, searchPolicies, findByCspPathFragment } from './db';
import { translateKey, normalizeKey, splitValueSegment, buildMetadata } from './parser';
import { PolicyMetadata } from './types';
import { msgraphKbClient } from './msgraph-client';
import { buildKnowledgeBase } from './kb-builder';
import { extractAndTranslate } from './extractor';
import { suggestPolicies } from './suggestor';

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

// ── Tool: refresh_kb ─────────────────────────────────────────────────────────
server.tool(
  'refresh_kb',
  'Rebuilds the local knowledge base by querying msgraph-kb with all predefined search terms and persisting every result. Requires MSGRAPH_KB_COMMAND to be set. Use force=true to overwrite existing records with fresh data from msgraph-kb.',
  {
    force: z.boolean().optional().default(false).describe('When true, overwrite existing records with fresh data from msgraph-kb. When false (default), only add new records that are not already in the database.'),
  },
  async ({ force }) => {
    if (!msgraphKbClient.isConfigured()) {
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              success: false,
              message: 'msgraph-kb is not configured. Set MSGRAPH_KB_COMMAND (and optionally MSGRAPH_KB_ARGS) environment variables to enable KB building.',
            }, null, 2),
          },
        ],
      };
    }

    const stats = await buildKnowledgeBase(msgraphKbClient, force);
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            success: true,
            message: `KB refresh complete. Searched ${stats.terms_searched} term(s), found ${stats.results_found} result(s), upserted ${stats.records_upserted} record(s)${stats.errors > 0 ? `, ${stats.errors} error(s)` : ''}.`,
            stats,
          }, null, 2),
        },
      ],
    };
  }
);

// ── Tool: extract_and_translate ──────────────────────────────────────────────
server.tool(
  'extract_and_translate',
  'Extracts all OMA-URI/CSP paths from a block of text (logs, XML, JSON, Event Viewer dumps) and translates each one. Returns resolved policy metadata and a list of unrecognized paths.',
  {
    text: z.string().describe('Freeform text to scan for OMA-URI/CSP paths (Event Viewer XML, MDM diagnostic output, raw JSON export, log files, etc.)'),
  },
  async ({ text }) => {
    const result = extractAndTranslate(text);
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  }
);

// ── Tool: suggest_policy ─────────────────────────────────────────────────────
server.tool(
  'suggest_policy',
  "Given a plain-English security or configuration goal (e.g. 'block USB storage on kiosk devices'), returns matching CSP policies with recommended production values and reasoning.",
  {
    goal: z.string().describe("Plain-English security or configuration goal, e.g. 'block USB storage on kiosk devices', 'require BitLocker on all laptops'"),
    context: z.string().optional().describe("Optional: device type, OS, environment (e.g. 'Windows 11 shared kiosk, no user accounts')"),
    limit: z.number().int().min(1).max(20).optional().default(5).describe('Maximum number of suggestions to return (default 5)'),
  },
  async ({ goal, context, limit }) => {
    const result = suggestPolicies(goal, context, limit);
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(result, null, 2),
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
  process.stderr.write('IntuneRosetta MCP server started\n');

  if (msgraphKbClient.isConfigured()) {
    process.stderr.write(`msgraph-kb configured (MSGRAPH_KB_COMMAND=${process.env['MSGRAPH_KB_COMMAND']})\n`);
    // Build the full KB in the background — non-blocking so the server is
    // immediately ready to accept requests while the KB populates.
    buildKnowledgeBase(msgraphKbClient).then((stats) => {
      process.stderr.write(
        `KB build complete: ${stats.terms_searched} terms, ${stats.results_found} results, ${stats.records_upserted} upserted${stats.errors > 0 ? `, ${stats.errors} errors` : ''}\n`,
      );
    }).catch((err: unknown) => {
      process.stderr.write(`KB build failed: ${err}\n`);
    });
  }
}

main().catch((err) => {
  process.stderr.write(`Fatal error: ${err}\n`);
  process.exit(1);
});

