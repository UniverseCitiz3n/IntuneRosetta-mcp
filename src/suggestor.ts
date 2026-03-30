import { PolicyMetadata, PolicyRecord, ValueMap } from './types';
import { searchPolicies } from './db';
import { buildMetadata, splitValueSegment } from './parser';

// ─── Stop words ──────────────────────────────────────────────────────────────
const STOP_WORDS = new Set([
  'a', 'an', 'the', 'and', 'or', 'to', 'in', 'on', 'for', 'with', 'is',
  'are', 'that', 'this', 'from', 'by', 'of', 'at', 'as', 'be', 'it', 'its',
  'not', 'all', 'my', 'has', 'have', 'can', 'should', 'want', 'need', 'make',
  'will', 'do', 'i', 'we', 'their', 'they', 'use', 'using', 'used', 'how',
  'what', 'which', 'when', 'where', 'set', 'get', 'so', 'if', 'any', 'more',
  'into', 'about', 'up', 'out',
]);

/**
 * Extract meaningful tokens from plain-English input.
 * Strips stop words and tokens shorter than 2 characters.
 */
export function extractTokens(input: string): string[] {
  return input
    .toLowerCase()
    .split(/[\s\p{P}]+/u)
    .filter((t) => t.length >= 2 && !STOP_WORDS.has(t));
}

// ─── Value preference ────────────────────────────────────────────────────────
// Ordered from most-preferred (enforce) to least-preferred (disable).
// Comparison is done case-insensitively against the value map *values*.
const VALUE_PREFERENCE: string[] = [
  'block', 'enabled', 'required', 'deny', 'enforce', 'on', 'true', 'yes',
  'allow', 'permitted',
  'audit', 'warn', 'monitor', 'report', 'notify',
  'disabled', 'off', 'false', 'no', 'not configured',
];

function preferenceScore(displayValue: string): number {
  const lower = displayValue.toLowerCase();
  const idx = VALUE_PREFERENCE.findIndex((p) => lower.startsWith(p) || lower === p);
  return idx === -1 ? VALUE_PREFERENCE.length : idx;
}

export interface RecommendedValue {
  key: string;       // value_map key (e.g. "1")
  value: string;     // human-readable label (e.g. "Block")
}

/**
 * Pick the most production-appropriate value from a value map.
 * Prefers "Block" / "Enabled" / "Required" over "Audit" / "Disabled".
 * Returns null when the map is empty.
 */
export function pickRecommendedValue(valueMap: ValueMap): RecommendedValue | null {
  const entries = Object.entries(valueMap);
  if (entries.length === 0) return null;

  const sorted = entries.slice().sort(([, a], [, b]) => preferenceScore(a) - preferenceScore(b));
  const [key, value] = sorted[0];
  return { key, value };
}

/**
 * Build a short human-readable reasoning string for the chosen recommended value.
 */
export function buildReasoning(recommended: RecommendedValue, valueMap: ValueMap): string {
  const lower = recommended.value.toLowerCase();

  if (lower.startsWith('block')) {
    const audit = Object.entries(valueMap).find(([, v]) => v.toLowerCase().startsWith('audit'));
    const auditHint = audit ? ` Use ${audit[1]} (value ${audit[0]}) first in pilot environments.` : '';
    return `Block mode enforces the policy restriction.${auditHint}`;
  }
  if (lower.startsWith('enabled')) {
    const disabled = Object.entries(valueMap).find(([, v]) => v.toLowerCase().startsWith('disabled'));
    return `Enabled activates the policy setting.${disabled ? ' Set to Disabled to turn it off.' : ''}`;
  }
  if (lower.startsWith('required')) {
    return 'Required makes this setting mandatory on managed devices.';
  }
  if (lower.startsWith('deny')) {
    return 'Deny prevents the action and is the most restrictive option.';
  }
  if (lower.startsWith('enforce')) {
    return 'Enforce applies the policy; less restrictive options are available for piloting.';
  }
  if (lower.startsWith('audit')) {
    return 'Audit logs events without enforcement — ideal for piloting before switching to Block.';
  }
  if (lower.startsWith('warn')) {
    return 'Warn alerts the user without blocking; consider Block for stricter production posture.';
  }
  if (lower.startsWith('disabled') || lower.startsWith('off') || lower === 'false' || lower === '0') {
    return `${recommended.value} turns the policy off. Verify this matches your security posture.`;
  }
  return `Value "${recommended.value}" is the most enforcement-oriented option available.`;
}

// ─── Scoring ─────────────────────────────────────────────────────────────────

/**
 * Score a policy record against the provided input tokens.
 *
 * Scoring criteria:
 * - +1 for each token that appears in the record's name / description /
 *   category / normalized_key
 * - +0.5 bonus when the record has a non-empty value_map (more actionable)
 * - -2 penalty when the record is deprecated
 */
export function scoreRecord(record: PolicyRecord, tokens: string[]): number {
  const haystack = [
    record.name,
    record.description,
    record.category,
    record.normalized_key,
  ]
    .join(' ')
    .toLowerCase();

  let score = 0;
  for (const token of tokens) {
    if (haystack.includes(token)) score += 1;
  }

  // Bonus for having actionable value choices
  try {
    const vm = JSON.parse(record.value_map) as ValueMap;
    if (Object.keys(vm).length > 0) score += 0.5;
  } catch {
    // invalid JSON value_map — ignore
  }

  // Deprecation penalty
  if (record.is_deprecated) score -= 2;

  return score;
}

/**
 * Convert a normalised score into a confidence level.
 */
export function getConfidence(score: number, tokens: string[]): 'high' | 'medium' | 'low' {
  if (tokens.length === 0) return 'low';
  const ratio = score / tokens.length;
  if (ratio >= 0.5) return 'high';
  if (ratio >= 0.2) return 'medium';
  return 'low';
}

// ─── Public API ──────────────────────────────────────────────────────────────

export interface PolicySuggestion {
  policy: PolicyMetadata;
  recommended_value: string | null;
  recommended_value_reasoning: string;
  confidence: 'high' | 'medium' | 'low';
}

export interface SuggestPolicyResult {
  goal: string;
  suggestions: PolicySuggestion[];
}

/**
 * Accept a plain-English goal (+ optional context) and return the top matching
 * CSP policy records with recommended production values and reasoning.
 *
 * Works entirely against the local SQLite DB — no external LLM calls.
 */
export function suggestPolicies(
  goal: string,
  context?: string,
  limit = 5,
): SuggestPolicyResult {
  const combined = context ? `${goal} ${context}` : goal;
  const tokens = extractTokens(combined);

  if (tokens.length === 0) {
    return { goal, suggestions: [] };
  }

  // Stage 1: collect candidates via DB search for each token
  const seen = new Set<string>();
  const candidates: PolicyRecord[] = [];

  for (const token of tokens) {
    const results = searchPolicies(token, 30);
    for (const r of results) {
      if (!seen.has(r.normalized_key)) {
        seen.add(r.normalized_key);
        candidates.push(r);
      }
    }
  }

  // Stage 2: score and rank candidates
  const scored = candidates
    .map((r) => ({ record: r, score: scoreRecord(r, tokens) }))
    .filter(({ score }) => score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, limit);

  const suggestions: PolicySuggestion[] = scored.map(({ record, score }) => {
    const { valueSegment } = splitValueSegment(record.normalized_key);
    const metadata = buildMetadata(record, valueSegment);

    let valueMap: ValueMap = {};
    try {
      valueMap = JSON.parse(record.value_map) as ValueMap;
    } catch {
      // ignore
    }

    const rec = pickRecommendedValue(valueMap);
    const recommended_value = rec ? rec.value : null;
    const recommended_value_reasoning = rec
      ? buildReasoning(rec, valueMap)
      : 'No discrete values are defined for this policy; configure the raw value directly.';

    return {
      policy: metadata,
      recommended_value,
      recommended_value_reasoning,
      confidence: getConfidence(score, tokens),
    };
  });

  return { goal, suggestions };
}
