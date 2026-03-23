import { MsgraphKbClient, GraphApiResult } from './msgraph-client';
import { upsertPolicy, findByKey } from './db';
import { PolicyRecord } from './types';

/**
 * Comprehensive list of Intune / Windows policy search terms.
 * These are used to bulk-query msgraph-kb at startup so the KB is fully
 * populated before any translation requests arrive.
 */
export const KB_SEARCH_TERMS: string[] = [
  'intune device configuration policy',
  'defender antivirus realtime protection',
  'attack surface reduction rules',
  'bitlocker drive encryption recovery',
  'LAPS local administrator password',
  'windows firewall network policy',
  'windows update delivery optimization',
  'smartscreen application guard',
  'endpoint security configuration profile',
  'device compliance conditional access',
  'privacy application permissions settings',
  'credential guard account protection',
  'network protection exploit guard',
  'controlled folder access ransomware',
  'advanced threat protection settings',
  'device health attestation enrollment',
  'application control applocker policy',
  'identity protection pin policy',
  'kiosk mode assigned access',
  'administrative templates group policy',
];

export interface KbBuildStats {
  terms_searched: number;
  results_found: number;
  records_upserted: number;
  errors: number;
}

/**
 * Derive a stable, DB-friendly normalized key from a Graph API path.
 *
 * Examples:
 *   /deviceManagement/managedDevices/{managedDevice-id}/rotateLocalAdminPassword
 *     → devicemanagement_manageddevices_rotatelocaladminpassword
 *   /deviceManagement/configurationSettings
 *     → devicemanagement_configurationsettings
 */
export function graphPathToNormalizedKey(graphPath: string): string {
  return graphPath
    .replace(/\{[^}]+\}/g, '')  // strip {path-params}
    .replace(/^\//, '')          // strip leading slash
    .replace(/\//g, '_')         // slashes → underscores
    .replace(/_+/g, '_')         // collapse consecutive underscores
    .replace(/_+$/, '')          // strip trailing underscores
    .toLowerCase();
}

/**
 * Infer a human-readable policy category from the Graph API path and derived key.
 */
function inferCategory(normalizedKey: string, graphPath: string): string {
  const k = normalizedKey.toLowerCase();
  const g = graphPath.toLowerCase();

  if (k.startsWith('device_vendor_msft_defender_configuration')) return 'Defender Configuration';
  if (k.startsWith('device_vendor_msft_policy_config_admx')) return 'ADMX';
  if (k.includes('attacksurface') || k.includes('asr')) return 'Defender ASR';
  if (k.includes('defender') || g.includes('defender')) return 'Defender';
  if (k.includes('bitlocker') || g.includes('bitlocker') || g.includes('encryption')) return 'BitLocker';
  if (k.includes('laps') || k.includes('localadmin') || g.includes('localadmin')) return 'LAPS';
  if (k.includes('firewall') || g.includes('firewall')) return 'Windows Firewall';
  if (k.includes('smartscreen') || g.includes('smartscreen')) return 'SmartScreen';
  if (k.includes('update') || g.includes('update')) return 'Windows Update';
  if (k.includes('applocker') || g.includes('applocker')) return 'AppLocker';
  if (k.includes('privacy') || g.includes('privacy')) return 'Privacy';
  if (k.includes('credential') || k.includes('identity') || k.includes('pin')) return 'Account Protection';
  if (k.includes('compliance') || g.includes('compliance')) return 'Device Compliance';
  if (k.includes('kiosk') || k.includes('assignedaccess')) return 'Kiosk';
  if (g.includes('devicemanagement') || g.includes('intune')) return 'Intune';

  return 'Windows Policy';
}

/**
 * Build a Microsoft Learn docs URL from a Graph API path.
 *
 * e.g. /deviceManagement/managedDevices/{id}/rotateLocalAdminPassword
 *   → https://learn.microsoft.com/en-us/graph/api/devicemanagement-manageddevice-rotatelocaladminpassword
 */
function buildDocsUrl(graphPath: string): string {
  if (!graphPath) return '';
  const slug = graphPath
    .replace(/\{[^}]+\}/g, '')
    .replace(/\/+/g, '-')
    .replace(/^-|-$/g, '')
    .toLowerCase();
  return `https://learn.microsoft.com/en-us/graph/api/${slug}`;
}

/**
 * Map a single Graph API result to a PolicyRecord.
 * The normalized_key is derived from the Graph API path.
 */
export function graphApiResultToRecord(result: GraphApiResult): Omit<PolicyRecord, 'id'> {
  const normalizedKey = graphPathToNormalizedKey(result.path);
  const description = result.description ?? result.summary ?? '';
  const name = description.length > 0 && description.length < 120
    ? description
    : result.summary;

  return {
    normalized_key: normalizedKey,
    name,
    description,
    csp_path: result.path,
    category: inferCategory(normalizedKey, result.path),
    docs_url: buildDocsUrl(result.path),
    value_map: '{}',
  };
}

/**
 * Eagerly build the local knowledge base by querying msgraph-kb with all
 * KB_SEARCH_TERMS at once and persisting every result.
 *
 * This replaces the previous per-request lazy enrichment: the entire KB is
 * populated in one pass at startup (or on demand via the refresh_kb tool).
 *
 * @param client  - configured MsgraphKbClient
 * @param force   - when true, overwrite records that already exist in the DB;
 *                  when false (default), skip existing records to avoid
 *                  overwriting manually curated data
 * @returns KbBuildStats summary of what was fetched and stored
 */
export async function buildKnowledgeBase(
  client: MsgraphKbClient,
  force = false,
): Promise<KbBuildStats> {
  const stats: KbBuildStats = {
    terms_searched: 0,
    results_found: 0,
    records_upserted: 0,
    errors: 0,
  };

  if (!client.isConfigured()) return stats;

  // Deduplicate across terms so a path appearing in multiple searches is only written once
  const seenPaths = new Set<string>();

  for (const term of KB_SEARCH_TERMS) {
    stats.terms_searched++;
    try {
      const results = await client.searchGraphApis(term, 100);
      stats.results_found += results.length;

      for (const result of results) {
        if (seenPaths.has(result.path)) continue;
        seenPaths.add(result.path);

        const record = graphApiResultToRecord(result);
        if (!record.normalized_key) continue;

        if (!force && findByKey(record.normalized_key)) continue;

        upsertPolicy(record);
        stats.records_upserted++;
      }
    } catch {
      stats.errors++;
    }
  }

  return stats;
}
