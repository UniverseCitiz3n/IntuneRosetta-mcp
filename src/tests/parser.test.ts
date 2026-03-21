import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeKey, splitValueSegment, translateKey, resolveValue, reconstructCspPath } from '../parser';
import { seedDatabase, searchPolicies, findByKey } from '../db';

// Use an in-memory / temp database for tests
process.env['NODE_ENV'] = 'test';

describe('normalizeKey', () => {
  it('strips device_vendor_msft_ prefix', () => {
    assert.equal(
      normalizeKey('device_vendor_msft_policy_config_defender_allowrealtimemonitoring'),
      'policy_config_defender_allowrealtimemonitoring'
    );
  });

  it('strips vendor_msft_ prefix', () => {
    assert.equal(
      normalizeKey('vendor_msft_laps_policies_backupdirectory'),
      'laps_policies_backupdirectory'
    );
  });

  it('lowercases input', () => {
    assert.equal(
      normalizeKey('DEVICE_VENDOR_MSFT_Policy_Config_Defender_AllowRealTimeMonitoring'),
      'policy_config_defender_allowrealtimemonitoring'
    );
  });

  it('returns unchanged if no known prefix', () => {
    assert.equal(normalizeKey('laps_policies_backupdirectory'), 'laps_policies_backupdirectory');
  });
});

describe('splitValueSegment', () => {
  it('extracts numeric trailing segment', () => {
    const { baseKey, valueSegment } = splitValueSegment('policy_config_defender_puaprotection_2');
    assert.equal(baseKey, 'policy_config_defender_puaprotection');
    assert.equal(valueSegment, '2');
  });

  it('handles no trailing segment', () => {
    const { baseKey, valueSegment } = splitValueSegment('policy_config_defender_puaprotection');
    assert.equal(baseKey, 'policy_config_defender_puaprotection');
    assert.equal(valueSegment, undefined);
  });

  it('extracts boolean trailing segment (true)', () => {
    const { baseKey, valueSegment } = splitValueSegment('policy_config_firewall_enable_true');
    assert.equal(baseKey, 'policy_config_firewall_enable');
    assert.equal(valueSegment, 'true');
  });

  it('handles key with zero value', () => {
    const { baseKey, valueSegment } = splitValueSegment('policy_config_defender_allowcloudprotection_0');
    assert.equal(baseKey, 'policy_config_defender_allowcloudprotection');
    assert.equal(valueSegment, '0');
  });
});

describe('resolveValue', () => {
  const valueMapJson = JSON.stringify({ '0': 'Disabled', '1': 'Block', '2': 'Audit', '6': 'Warn' });

  it('resolves a known value', () => {
    assert.equal(resolveValue('2', valueMapJson), 'Audit');
  });

  it('returns raw value when not in map', () => {
    assert.equal(resolveValue('99', valueMapJson), '99');
  });

  it('returns "Not specified" for undefined value', () => {
    assert.equal(resolveValue(undefined, valueMapJson), 'Not specified');
  });
});

describe('reconstructCspPath', () => {
  it('reconstructs policy_config_ prefix correctly', () => {
    const path = reconstructCspPath('policy_config_defender_allowrealtimemonitoring');
    assert.ok(path.startsWith('./Device/Vendor/MSFT/Policy/Config/'));
  });

  it('reconstructs laps_ prefix correctly', () => {
    const path = reconstructCspPath('laps_policies_backupdirectory');
    assert.ok(path.startsWith('./Device/Vendor/MSFT/LAPS/'));
  });
});

describe('translateKey (integration)', () => {
  before(() => {
    seedDatabase();
  });

  it('translates a fully known ASR rule key with value', () => {
    const result = translateKey(
      'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts_2'
    );
    assert.equal(result.category, 'Defender ASR');
    assert.equal(result.value, 'Audit');
    assert.ok(result.name.toLowerCase().includes('obfuscated'));
    assert.ok(result.docs_url.startsWith('https://'));
  });

  it('translates a LAPS key with enum value', () => {
    const result = translateKey('device_vendor_msft_laps_policies_backupdirectory_1');
    assert.equal(result.category, 'LAPS');
    assert.equal(result.value, 'Azure Active Directory');
  });

  it('translates a BitLocker key', () => {
    const result = translateKey('device_vendor_msft_policy_config_bitlocker_requiredeviceencryption_1');
    assert.equal(result.category, 'BitLocker');
    assert.equal(result.value, 'Required');
  });

  it('returns best-effort metadata for unknown key', () => {
    const result = translateKey('device_vendor_msft_policy_config_privacy_letappsaccesscamera_0');
    assert.equal(result.category, 'Unknown');
    assert.ok(result.csp_path.includes('Policy/Config/Privacy'));
    assert.equal(result.value, '0');
  });

  it('handles key without value suffix', () => {
    const result = translateKey('device_vendor_msft_policy_config_defender_allowrealtimemonitoring');
    assert.equal(result.category, 'Defender');
    assert.equal(result.value, 'Not specified');
  });
});

describe('searchPolicies (integration)', () => {
  before(() => {
    seedDatabase();
  });

  it('finds BitLocker policies by keyword', () => {
    const results = searchPolicies('bitlocker', 10);
    assert.ok(results.length > 0);
    assert.ok(results.every((r) => r.category === 'BitLocker'));
  });

  it('finds LAPS policies', () => {
    const results = searchPolicies('laps', 10);
    assert.ok(results.length > 0);
    assert.ok(results.every((r) => r.category === 'LAPS'));
  });

  it('finds ASR policies by description keyword', () => {
    const results = searchPolicies('obfuscated', 5);
    assert.ok(results.length > 0);
  });

  it('returns empty array for non-matching query', () => {
    const results = searchPolicies('zzznomatchzzz', 10);
    assert.equal(results.length, 0);
  });
});

describe('findByKey (integration)', () => {
  before(() => {
    seedDatabase();
  });

  it('finds a seeded policy by normalised key', () => {
    const record = findByKey('policy_config_defender_allowrealtimemonitoring');
    assert.ok(record !== undefined);
    assert.equal(record!.name, 'Defender: Allow real-time monitoring');
  });

  it('returns undefined for unknown key', () => {
    const record = findByKey('zzz_unknown_key_zzz');
    assert.equal(record, undefined);
  });
});
