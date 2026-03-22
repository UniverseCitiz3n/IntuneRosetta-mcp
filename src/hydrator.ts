import { GraphApiResult, MsgraphKbClient } from './msgraph-client';
import { PolicyRecord, ValueMap } from './types';
import { upsertPolicy, findByKey } from './db';
import { normalizeKey, splitValueSegment } from './parser';

/**
 * Strip common low-signal segments from a normalised CSP key so the remaining
 * tokens are meaningful search terms for msgraph-kb.
 *
 * Examples:
 *   policy_config_defender_attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts
 *   → "defender attacksurfacereductionrules blockexecutionofpotentiallyobfuscatedscripts"
 *
 *   laps_policies_backupdirectory  → "LAPS backup directory"
 *   policy_config_bitlocker_requiredeviceencryption → "bitlocker requiredeviceencryption"
 */
export function extractSearchKeywords(normalizedKey: string): string {
  const { baseKey } = splitValueSegment(normalizedKey);

  // Strip well-known low-signal prefixes
  const withoutPolicyConfig = baseKey.replace(/^policy_config_/, '');
  const withoutPolicies = withoutPolicyConfig.replace(/^([a-z]+)_policies_/, '$1 ');

  // Replace remaining underscores with spaces for readability
  return withoutPolicies.replace(/_/g, ' ').trim();
}

/**
 * Infer a policy category from a normalised key or Graph API path.
 */
function inferCategory(normalizedKey: string, graphPath: string): string {
  const k = normalizedKey.toLowerCase();
  const g = graphPath.toLowerCase();

  if (k.includes('attacksurfacereduction') || k.includes('asr')) return 'Defender ASR';
  if (k.includes('defender') || g.includes('defender')) return 'Defender';
  if (k.includes('bitlocker') || g.includes('bitlocker') || g.includes('encryption')) return 'BitLocker';
  if (k.startsWith('laps') || g.includes('localadmin') || g.includes('laps')) return 'LAPS';
  if (k.includes('firewall') || g.includes('firewall')) return 'Windows Firewall';
  if (k.includes('smartscreen') || g.includes('smartscreen')) return 'SmartScreen';
  if (k.includes('update') || g.includes('update')) return 'Windows Update';
  if (k.includes('applocker') || g.includes('applocker')) return 'AppLocker';
  if (k.includes('privacy') || g.includes('privacy')) return 'Privacy';
  if (g.includes('devicemanagement') || g.includes('intune')) return 'Intune';

  return 'Windows Policy';
}

/**
 * Build a Microsoft Learn docs URL from a Graph API path.
 *
 * e.g. /deviceManagement/managedDevices/{id}/rotateLocalAdminPassword
 *   → https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-rotatelocaladminpassword
 */
function buildDocsUrl(graphPath: string): string {
  if (!graphPath) return '';
  // Normalise: remove path params, lowercase, strip leading slash
  const slug = graphPath
    .replace(/\{[^}]+\}/g, '')
    .replace(/\/+/g, '-')
    .replace(/^-|-$/g, '')
    .toLowerCase();
  return `https://learn.microsoft.com/en-us/graph/api/${slug}`;
}

/**
 * Map a Graph API search result to a PolicyRecord for the given CSP key.
 *
 * The CSP path is preserved from the original key; the Graph API data enriches
 * the name, description, category, and docs_url fields.
 */
function mapGraphResultToPolicyRecord(
  normalizedKey: string,
  cspPath: string,
  result: GraphApiResult,
  existingValueMap: ValueMap = {},
): Omit<PolicyRecord, 'id'> {
  const description = result.description ?? result.summary ?? '';

  // Human-readable name: prefer description sentence over the raw API summary
  const name = description.length > 0 && description.length < 120
    ? description
    : result.summary;

  return {
    normalized_key: normalizedKey,
    name,
    description,
    csp_path: cspPath,
    category: inferCategory(normalizedKey, result.path),
    docs_url: buildDocsUrl(result.path),
    value_map: JSON.stringify(existingValueMap),
  };
}

/**
 * Reconstruct a dotted OMA-URI CSP path from a normalised key (best-effort).
 */
function reconstructCspPathFromKey(normalizedKey: string): string {
  const { baseKey } = splitValueSegment(normalizedKey);
  if (baseKey.startsWith('policy_config_')) {
    const rest = baseKey.slice('policy_config_'.length);
    const segments = rest.split('_');
    const caps = segments.map((s) => s.charAt(0).toUpperCase() + s.slice(1));
    return `./Device/Vendor/MSFT/Policy/Config/${caps.join('/')}`;
  }
  if (baseKey.startsWith('laps_')) {
    const rest = baseKey.slice('laps_'.length);
    const segments = rest.split('_');
    const caps = segments.map((s) => s.charAt(0).toUpperCase() + s.slice(1));
    return `./Device/Vendor/MSFT/LAPS/${caps.join('/')}`;
  }
  const segments = baseKey.split('_');
  const caps = segments.map((s) => s.charAt(0).toUpperCase() + s.slice(1));
  return `./Device/Vendor/MSFT/${caps.join('/')}`;
}

/**
 * Query msgraph-kb for the given CSP key, cache the best matching result,
 * and return the upserted PolicyRecord.
 *
 * Returns undefined if msgraph-kb is not configured, returns no results,
 * or the key was already in the database.
 */
export async function hydrateFromMsgraphKb(
  client: MsgraphKbClient,
  rawKey: string,
): Promise<Omit<PolicyRecord, 'id'> | undefined> {
  if (!client.isConfigured()) return undefined;

  const normalized = normalizeKey(rawKey);
  const { baseKey } = splitValueSegment(normalized);

  // Skip if already in DB
  if (findByKey(baseKey)) return undefined;

  const query = extractSearchKeywords(baseKey);
  if (!query) return undefined;

  let results: GraphApiResult[] = [];
  try {
    results = await client.searchGraphApis(query, 3);
  } catch {
    // msgraph-kb unavailable — silently skip enrichment
    return undefined;
  }

  if (results.length === 0) return undefined;

  // Pick the best result: prefer entries that have a non-empty description
  const best = results.find((r) => r.description && r.description.length > 0) ?? results[0];
  const cspPath = reconstructCspPathFromKey(baseKey);
  const record = mapGraphResultToPolicyRecord(baseKey, cspPath, best);

  upsertPolicy(record);
  return record;
}

/**
 * Store an explicitly provided policy record into the database.
 * Used by the `hydrate_db` MCP tool so that the LLM can pipe msgraph-kb
 * results directly into the IntuneRosetta store.
 */
export function hydratePolicyRecord(record: Omit<PolicyRecord, 'id'>): void {
  upsertPolicy(record);
}
