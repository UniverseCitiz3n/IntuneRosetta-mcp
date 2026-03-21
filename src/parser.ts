import { PolicyMetadata, PolicyRecord, ValueMap } from './types';
import { findByKey, upsertPolicy } from './db';

const MSFT_PREFIX = 'device_vendor_msft_';
const MSFT_PREFIX_SHORT = 'vendor_msft_';

/**
 * Normalise a raw underscore-delimited OMA-URI key into a consistent DB key.
 *
 * Steps:
 *  1. Lowercase everything
 *  2. Strip leading "device_vendor_msft_" or "vendor_msft_" prefix
 *  3. The resulting string is the normalised key used for DB lookups
 */
export function normalizeKey(raw: string): string {
  const lower = raw.toLowerCase().trim();
  if (lower.startsWith(MSFT_PREFIX)) {
    return lower.slice(MSFT_PREFIX.length);
  }
  if (lower.startsWith(MSFT_PREFIX_SHORT)) {
    return lower.slice(MSFT_PREFIX_SHORT.length);
  }
  return lower;
}

/**
 * Extract a trailing numeric (or short) value segment from the normalised key.
 *
 * For example:
 *   "policy_config_defender_puaprotection_2"  →  { baseKey: "policy_config_defender_puaprotection", valueSegment: "2" }
 *   "policy_config_defender_puaprotection"    →  { baseKey: "policy_config_defender_puaprotection", valueSegment: undefined }
 */
export function splitValueSegment(normalizedKey: string): { baseKey: string; valueSegment: string | undefined } {
  // Match a trailing _<token> where the token is a numeric value (e.g. _0, _1, _2) or
  // a boolean string (e.g. _true, _false). Numeric values use \d+ which covers all integer keys.
  const match = normalizedKey.match(/^(.*?)_(\d+|true|false)$/);
  if (match) {
    return { baseKey: match[1], valueSegment: match[2] };
  }
  return { baseKey: normalizedKey, valueSegment: undefined };
}

/**
 * Reconstruct a dotted OMA-URI CSP path from a normalised underscore key.
 *
 * This is a best-effort reconstruction. The seeded canonical paths take precedence.
 */
export function reconstructCspPath(normalizedKey: string): string {
  // Map common top-level segments
  if (normalizedKey.startsWith('policy_config_')) {
    const rest = normalizedKey.slice('policy_config_'.length);
    const segments = rest.split('_');
    // Capitalise each segment
    const capitalised = segments.map((s) => s.charAt(0).toUpperCase() + s.slice(1));
    // The first two segments become the policy area + setting name (heuristic)
    return `./Device/Vendor/MSFT/Policy/Config/${capitalised.join('/')}`;
  }
  if (normalizedKey.startsWith('laps_')) {
    const rest = normalizedKey.slice('laps_'.length);
    const segments = rest.split('_');
    const capitalised = segments.map((s) => s.charAt(0).toUpperCase() + s.slice(1));
    return `./Device/Vendor/MSFT/LAPS/${capitalised.join('/')}`;
  }
  // Generic fallback
  const segments = normalizedKey.split('_');
  const capitalised = segments.map((s) => s.charAt(0).toUpperCase() + s.slice(1));
  return `./Device/Vendor/MSFT/${capitalised.join('/')}`;
}

/**
 * Resolve a value string against a value map.
 * Returns a descriptive string if found, otherwise returns the raw value.
 */
export function resolveValue(valueSegment: string | undefined, valueMapJson: string): string {
  if (valueSegment === undefined) return 'Not specified';
  let map: ValueMap = {};
  try {
    map = JSON.parse(valueMapJson) as ValueMap;
  } catch {
    // ignore
  }
  return map[valueSegment] ?? valueSegment;
}

/**
 * Build a PolicyMetadata object from a PolicyRecord + optional value segment.
 */
export function buildMetadata(record: PolicyRecord, valueSegment: string | undefined): PolicyMetadata {
  return {
    name: record.name,
    description: record.description,
    value: resolveValue(valueSegment, record.value_map),
    csp_path: record.csp_path,
    category: record.category,
    docs_url: record.docs_url,
  };
}

/**
 * Translate a raw CSP key string into structured PolicyMetadata.
 *
 * Lookup order:
 *  1. Exact match on normalised key (with value segment stripped)
 *  2. Exact match on full normalised key (value segment included)
 *  3. Return a "best-effort" reconstruction from the key itself
 */
export function translateKey(raw: string): PolicyMetadata {
  const normalised = normalizeKey(raw);
  const { baseKey, valueSegment } = splitValueSegment(normalised);

  // Try base key first (most common — key without value suffix)
  let record = findByKey(baseKey);
  if (record) {
    return buildMetadata(record, valueSegment);
  }

  // Try full normalised key (in case someone stored the whole thing)
  record = findByKey(normalised);
  if (record) {
    return buildMetadata(record, undefined);
  }

  // Best-effort: reconstruct from the key structure
  const cspPath = reconstructCspPath(baseKey);
  const humanName = baseKey
    .split('_')
    .map((s) => s.charAt(0).toUpperCase() + s.slice(1))
    .join(' ');

  return {
    name: humanName,
    description: 'No description available. Policy not found in local database.',
    value: valueSegment ?? 'Not specified',
    csp_path: cspPath,
    category: 'Unknown',
    docs_url: '',
  };
}

/**
 * Store a newly resolved policy into the database for future lookups.
 */
export function cachePolicy(raw: string, metadata: PolicyMetadata, valueMap: ValueMap = {}): void {
  const normalised = normalizeKey(raw);
  const { baseKey } = splitValueSegment(normalised);
  const existing = findByKey(baseKey);
  if (existing) return; // already cached

  upsertPolicy({
    normalized_key: baseKey,
    name: metadata.name,
    description: metadata.description,
    csp_path: metadata.csp_path,
    category: metadata.category,
    docs_url: metadata.docs_url,
    value_map: JSON.stringify(valueMap),
  });
}
