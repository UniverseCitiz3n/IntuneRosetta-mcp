import { PolicyMetadata } from './types';
import { findByKey } from './db';
import { normalizeKey, splitValueSegment, buildMetadata } from './parser';

const MSFT_PREFIX = 'device_vendor_msft_';

/**
 * URL-decode an input string handling partial / malformed encoding gracefully.
 * Each `%XX` percent-encoded sequence is decoded individually; invalid sequences
 * are left as-is rather than throwing.
 */
export function safeUrlDecode(input: string): string {
  return input.replace(/%[0-9A-Fa-f]{2}/g, (match) => {
    try {
      return decodeURIComponent(match);
    } catch {
      return match;
    }
  });
}

/**
 * Convert an OMA-URI CSP path (slash-separated) to a normalised underscore key.
 *
 * Example:
 *   `./Device/Vendor/MSFT/Policy/Config/Defender/SomePolicy`
 *   → `policy_config_defender_somepolicy`  (device_vendor_msft_ prefix stripped)
 */
export function cspPathToNormalizedKey(cspPath: string): string {
  // Strip optional leading "./" then convert slashes to underscores and lowercase
  const withoutLeading = cspPath.replace(/^\.[\\/]/, '');
  const underscored = withoutLeading.replace(/[\\/]+/g, '_').toLowerCase();
  // Re-use normalizeKey to strip the device_vendor_msft_ prefix so the
  // resulting string is consistent with DB normalised keys.
  return normalizeKey(underscored);
}

// Regex matching OMA-URI/CSP paths in freeform text.
// Handles both forward-slash and backslash (after normalisation) path separators.
const CSP_PATH_REGEX = /(?:\.[\\/])?(?:Device|User)\/Vendor\/MSFT\/[^\s"'<>,;)\]]+/g;

// Regex matching already-normalised underscore-form keys as produced by Intune exports.
// Supports all known MSFT vendor prefixes that `normalizeKey` can strip.
const CSP_KEY_REGEX = /\b(?:device_vendor_msft_|user_vendor_msft_|vendor_msft_)[a-z0-9_]+/g;

/**
 * Extract all OMA-URI / CSP paths from a block of text and return them as an
 * array of **normalised DB keys** (device_vendor_msft_ prefix stripped),
 * deduplicated.
 *
 * Handles:
 * - URL-encoded paths (`%2F` → `/`)
 * - Backslash path separators (`.\Device\...`)
 * - Quoted paths (`"./Device/..."`, `'./Device/...'`)
 * - Trailing punctuation artefacts (`.`, `,`, `)`, `]`, `>`)
 * - Serialised Intune export keys (`device_vendor_msft_...` already normalised)
 */
export function extractCspPaths(text: string): string[] {
  // Step 1: URL-decode (per %XX segment so partial encoding doesn't break everything)
  const decoded = safeUrlDecode(text);

  // Step 2: Normalise backslash path separators to forward slashes so the CSP
  // path regex matches regardless of the original platform separators.
  // We only replace backslashes that are inside what looks like a path
  // context (after Device/User prefix or after a dot-backslash prefix).
  const normalised = decoded
    .replace(/\.\\/g, './')                               // .\Device → ./Device
    .replace(/(Device|User|MSFT|[A-Za-z0-9])\\/g, '$1/'); // mid-path backslashes

  const seen = new Set<string>();
  const results: string[] = [];

  const addKey = (raw: string) => {
    // Strip surrounding single/double quotes
    let cleaned = raw.replace(/^['"]|['"]$/g, '');
    // Trim trailing punctuation artefacts
    cleaned = cleaned.replace(/[.,)\]>]+$/, '');
    if (!cleaned) return;
    const key = cspPathToNormalizedKey(cleaned);
    if (key && !seen.has(key)) {
      seen.add(key);
      results.push(key);
    }
  };

  // Match OMA-URI style paths
  const pathMatches = normalised.match(CSP_PATH_REGEX) ?? [];
  for (const m of pathMatches) {
    addKey(m);
  }

  // Match underscore-normalised keys (Intune export format)
  const keyMatches = normalised.match(CSP_KEY_REGEX) ?? [];
  for (const m of keyMatches) {
    const key = normalizeKey(m);
    if (key && !seen.has(key)) {
      seen.add(key);
      results.push(key);
    }
  }

  return results;
}

/**
 * Look up a normalised key in the DB (trying both with and without the
 * device_vendor_msft_ prefix, mirroring the translateKey lookup chain).
 */
function findRecord(normalizedKey: string) {
  return (
    findByKey(normalizedKey) ??
    findByKey(`${MSFT_PREFIX}${normalizedKey}`)
  );
}

export interface ExtractAndTranslateResult {
  found: PolicyMetadata[];
  unresolved: string[];
}

/**
 * Extract all OMA-URI/CSP paths from `text`, translate each against the local
 * DB, and return resolved metadata + a list of unrecognised keys.
 */
export function extractAndTranslate(text: string): ExtractAndTranslateResult {
  const keys = extractCspPaths(text);
  const found: PolicyMetadata[] = [];
  const unresolved: string[] = [];

  for (const key of keys) {
    const record = findRecord(key);
    if (record) {
      const { valueSegment } = splitValueSegment(record.normalized_key);
      found.push(buildMetadata(record, valueSegment));
    } else {
      unresolved.push(key);
    }
  }

  return { found, unresolved };
}
