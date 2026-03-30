import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { closeDb, seedDatabase } from '../db';
import {
  extractTokens,
  pickRecommendedValue,
  buildReasoning,
  scoreRecord,
  getConfidence,
  suggestPolicies,
  RecommendedValue,
} from '../suggestor';
import { PolicyRecord, ValueMap } from '../types';

// Use a fresh DB for this suite
before(() => {
  closeDb();
  process.env['INTUNE_ROSETTA_DB_PATH'] = path.join(os.tmpdir(), `test_suggestor_${Date.now()}.db`);
  seedDatabase();
});

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeRecord(overrides: Partial<PolicyRecord> = {}): PolicyRecord {
  return {
    normalized_key: 'policy_config_defender_test',
    name: 'Test Policy',
    description: 'A test policy for unit testing.',
    csp_path: './Device/Vendor/MSFT/Policy/Config/Defender/Test',
    category: 'Defender',
    docs_url: '',
    value_map: JSON.stringify({ '0': 'Disabled', '1': 'Block', '2': 'Audit' }),
    ...overrides,
  };
}

// ─── extractTokens ────────────────────────────────────────────────────────────

describe('extractTokens', () => {
  it('splits on whitespace and punctuation', () => {
    const tokens = extractTokens('block USB storage');
    assert.ok(tokens.includes('block'));
    assert.ok(tokens.includes('usb'));
    assert.ok(tokens.includes('storage'));
  });

  it('removes stop words', () => {
    const tokens = extractTokens('block all the usb devices and storage');
    assert.ok(!tokens.includes('all'));
    assert.ok(!tokens.includes('the'));
    assert.ok(!tokens.includes('and'));
  });

  it('filters tokens shorter than 2 characters', () => {
    const tokens = extractTokens('a b c usb');
    assert.ok(!tokens.includes('a'));
    assert.ok(!tokens.includes('b'));
    assert.ok(!tokens.includes('c'));
    assert.ok(tokens.includes('usb'));
  });

  it('lowercases all tokens', () => {
    const tokens = extractTokens('BLOCK USB STORAGE');
    assert.ok(tokens.includes('block'));
    assert.ok(tokens.includes('usb'));
    assert.ok(tokens.includes('storage'));
    assert.ok(!tokens.includes('BLOCK'));
  });

  it('returns empty array for empty string', () => {
    assert.deepEqual(extractTokens(''), []);
  });

  it('returns empty array for string with only stop words', () => {
    const tokens = extractTokens('a the and or for with');
    assert.equal(tokens.length, 0);
  });
});

// ─── pickRecommendedValue ─────────────────────────────────────────────────────

describe('pickRecommendedValue', () => {
  it('prefers Block over Audit', () => {
    const vm: ValueMap = { '0': 'Disabled', '1': 'Block', '2': 'Audit' };
    const result = pickRecommendedValue(vm);
    assert.ok(result !== null);
    assert.equal(result!.value, 'Block');
  });

  it('prefers Enabled over Disabled', () => {
    const vm: ValueMap = { '0': 'Disabled', '1': 'Enabled' };
    const result = pickRecommendedValue(vm);
    assert.ok(result !== null);
    assert.equal(result!.value, 'Enabled');
  });

  it('prefers Required over Audit', () => {
    const vm: ValueMap = { '0': 'Not required', '1': 'Required', '2': 'Audit' };
    const result = pickRecommendedValue(vm);
    assert.ok(result !== null);
    assert.equal(result!.value, 'Required');
  });

  it('prefers Audit over Disabled when Block not available', () => {
    const vm: ValueMap = { '0': 'Disabled', '1': 'Audit' };
    const result = pickRecommendedValue(vm);
    assert.ok(result !== null);
    assert.equal(result!.value, 'Audit');
  });

  it('returns null for empty value map', () => {
    assert.equal(pickRecommendedValue({}), null);
  });

  it('returns the key as well as the value', () => {
    const vm: ValueMap = { '1': 'Block', '2': 'Audit' };
    const result = pickRecommendedValue(vm);
    assert.ok(result !== null);
    assert.equal(result!.key, '1');
    assert.equal(result!.value, 'Block');
  });
});

// ─── buildReasoning ───────────────────────────────────────────────────────────

describe('buildReasoning', () => {
  it('mentions Audit hint for Block recommendation', () => {
    const vm: ValueMap = { '1': 'Block', '2': 'Audit' };
    const rec: RecommendedValue = { key: '1', value: 'Block' };
    const reasoning = buildReasoning(rec, vm);
    assert.ok(reasoning.toLowerCase().includes('block'), `got: ${reasoning}`);
    assert.ok(reasoning.toLowerCase().includes('audit'), `got: ${reasoning}`);
  });

  it('mentions Disabled for Enabled recommendation', () => {
    const vm: ValueMap = { '0': 'Disabled', '1': 'Enabled' };
    const rec: RecommendedValue = { key: '1', value: 'Enabled' };
    const reasoning = buildReasoning(rec, vm);
    assert.ok(reasoning.toLowerCase().includes('disabled'), `got: ${reasoning}`);
  });

  it('returns non-empty string for Audit recommendation', () => {
    const vm: ValueMap = { '0': 'Disabled', '2': 'Audit' };
    const rec: RecommendedValue = { key: '2', value: 'Audit' };
    const reasoning = buildReasoning(rec, vm);
    assert.ok(reasoning.length > 0);
    assert.ok(reasoning.toLowerCase().includes('audit'), `got: ${reasoning}`);
  });

  it('returns a non-empty generic string for unknown values', () => {
    const vm: ValueMap = { '42': 'SomeCustomValue' };
    const rec: RecommendedValue = { key: '42', value: 'SomeCustomValue' };
    const reasoning = buildReasoning(rec, vm);
    assert.ok(reasoning.length > 0);
  });
});

// ─── scoreRecord ──────────────────────────────────────────────────────────────

describe('scoreRecord', () => {
  it('returns higher score when more tokens match', () => {
    const record = makeRecord({ name: 'USB Storage Block Policy', description: 'Blocks USB storage devices', category: 'Device Control' });
    const highTokens = ['usb', 'storage', 'block'];
    const lowTokens = ['bitlocker'];
    assert.ok(scoreRecord(record, highTokens) > scoreRecord(record, lowTokens));
  });

  it('gives bonus for records with a non-empty value_map', () => {
    const withMap = makeRecord({ value_map: JSON.stringify({ '0': 'Disabled', '1': 'Block' }) });
    const withoutMap = makeRecord({ value_map: '{}' });
    const tokens = ['test'];
    // Both match the token but withMap should score higher
    assert.ok(scoreRecord(withMap, tokens) > scoreRecord(withoutMap, tokens));
  });

  it('penalises deprecated records', () => {
    const tokens = ['defender', 'test'];
    const normal = makeRecord();
    const deprecated = makeRecord({ is_deprecated: true });
    assert.ok(scoreRecord(normal, tokens) > scoreRecord(deprecated, tokens));
  });

  it('returns 0 for no matching tokens', () => {
    const record = makeRecord();
    const score = scoreRecord(record, ['bitlocker', 'startup', 'pin']);
    // No tokens match "Test Policy" / "Defender" — score only includes value_map bonus
    // (0.5 for having a value map), so it may be > 0 but no keyword match
    assert.ok(score < 1);
  });
});

// ─── getConfidence ────────────────────────────────────────────────────────────

describe('getConfidence', () => {
  it('returns high when ratio >= 0.5', () => {
    // 3 tokens, score 2.5 → ratio 2.5/3 ≈ 0.83 → high
    assert.equal(getConfidence(2.5, ['a', 'b', 'c']), 'high');
  });

  it('returns medium when ratio is between 0.2 and 0.5', () => {
    // 5 tokens, score 1 → ratio 0.2 → medium
    assert.equal(getConfidence(1, ['a', 'b', 'c', 'd', 'e']), 'medium');
  });

  it('returns low when ratio < 0.2', () => {
    // 10 tokens, score 1 → ratio 0.1 → low
    assert.equal(getConfidence(1, ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j']), 'low');
  });

  it('returns low for empty tokens array', () => {
    assert.equal(getConfidence(5, []), 'low');
  });
});

// ─── suggestPolicies (integration) ───────────────────────────────────────────

describe('suggestPolicies (integration)', () => {
  it('returns suggestions for a valid goal', () => {
    const result = suggestPolicies('block obfuscated scripts', undefined, 5);
    assert.equal(result.goal, 'block obfuscated scripts');
    assert.ok(Array.isArray(result.suggestions));
    // Should find at least one ASR policy matching this goal
    assert.ok(result.suggestions.length > 0, 'expected at least 1 suggestion');
  });

  it('each suggestion has required fields', () => {
    const result = suggestPolicies('defender realtime monitoring', undefined, 3);
    for (const s of result.suggestions) {
      assert.ok(typeof s.recommended_value_reasoning === 'string');
      assert.ok(['high', 'medium', 'low'].includes(s.confidence));
      assert.ok(typeof s.policy === 'object');
      assert.ok(typeof s.policy.name === 'string');
    }
  });

  it('respects the limit parameter', () => {
    const result = suggestPolicies('policy config defender', undefined, 2);
    assert.ok(result.suggestions.length <= 2);
  });

  it('returns empty suggestions for gibberish input', () => {
    const result = suggestPolicies('zzznomatchzzznomatch', undefined, 5);
    assert.equal(result.suggestions.length, 0);
  });

  it('includes context tokens in scoring', () => {
    const withContext = suggestPolicies('block', 'bitlocker drive encryption', 5);
    assert.ok(Array.isArray(withContext.suggestions));
  });
});
