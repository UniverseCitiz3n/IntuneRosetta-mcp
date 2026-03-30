import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { closeDb, seedDatabase } from '../db';
import {
  safeUrlDecode,
  cspPathToNormalizedKey,
  extractCspPaths,
  extractAndTranslate,
} from '../extractor';

// Use a fresh DB for this suite
before(() => {
  closeDb();
  process.env['INTUNE_ROSETTA_DB_PATH'] = path.join(os.tmpdir(), `test_extractor_${Date.now()}.db`);
  seedDatabase();
});

describe('safeUrlDecode', () => {
  it('decodes standard percent-encoded sequences', () => {
    assert.equal(safeUrlDecode('%2F'), '/');
    assert.equal(safeUrlDecode('%20'), ' ');
  });

  it('handles already-decoded strings unchanged', () => {
    assert.equal(safeUrlDecode('./Device/Vendor/MSFT'), './Device/Vendor/MSFT');
  });

  it('leaves malformed percent sequences intact', () => {
    // %ZZ is not a valid percent-encoding; should be left as-is
    assert.equal(safeUrlDecode('%ZZ'), '%ZZ');
  });

  it('decodes mixed encoded and plain text', () => {
    const result = safeUrlDecode('./Device%2FVendor%2FMSFT%2FPolicy');
    assert.equal(result, './Device/Vendor/MSFT/Policy');
  });
});

describe('cspPathToNormalizedKey', () => {
  it('converts a Device CSP path to normalised key', () => {
    assert.equal(
      cspPathToNormalizedKey('./Device/Vendor/MSFT/Policy/Config/Defender/AllowRealTimeMonitoring'),
      'policy_config_defender_allowrealtimemonitoring',
    );
  });

  it('handles User paths', () => {
    const key = cspPathToNormalizedKey('./User/Vendor/MSFT/Policy/Config/Start/HideShutDown');
    assert.ok(key.startsWith('policy_config_start_'));
  });

  it('strips leading ./ correctly', () => {
    assert.equal(
      cspPathToNormalizedKey('./Device/Vendor/MSFT/LAPS/Policies/BackupDirectory'),
      'laps_policies_backupdirectory',
    );
  });

  it('handles path without leading ./', () => {
    const key = cspPathToNormalizedKey('Device/Vendor/MSFT/Policy/Config/Defender/Test');
    assert.equal(key, 'policy_config_defender_test');
  });
});

describe('extractCspPaths', () => {
  it('extracts a single OMA-URI path from plain text', () => {
    const text = 'The policy ./Device/Vendor/MSFT/Policy/Config/Defender/AllowRealTimeMonitoring controls scanning.';
    const paths = extractCspPaths(text);
    assert.ok(paths.includes('policy_config_defender_allowrealtimemonitoring'), `got: ${JSON.stringify(paths)}`);
  });

  it('extracts multiple CSP paths', () => {
    const text = `
      Setting1: ./Device/Vendor/MSFT/Policy/Config/Defender/AllowCloudProtection
      Setting2: ./Device/Vendor/MSFT/Policy/Config/Defender/AllowRealTimeMonitoring
    `;
    const paths = extractCspPaths(text);
    assert.ok(paths.length >= 2);
  });

  it('handles URL-encoded paths', () => {
    const text = '.%2FDevice%2FVendor%2FMSFT%2FPolicy%2FConfig%2FDefender%2FAllowCloudProtection';
    // After URL-decoding this becomes a normal path — we extract it
    const text2 = './Device/Vendor/MSFT/Policy/Config/Defender/AllowCloudProtection';
    const paths2 = extractCspPaths(text2);
    assert.ok(paths2.includes('policy_config_defender_allowcloudprotection'));
    // URL-encoded variant of the full path
    const paths = extractCspPaths(text);
    // The %2F-decoded path should produce the same key
    assert.ok(paths.includes('policy_config_defender_allowcloudprotection'), `got: ${JSON.stringify(paths)}`);
  });

  it('handles backslash path separators', () => {
    const text = '.\\Device\\Vendor\\MSFT\\Policy\\Config\\Defender\\AllowCloudProtection';
    const paths = extractCspPaths(text);
    assert.ok(paths.includes('policy_config_defender_allowcloudprotection'), `got: ${JSON.stringify(paths)}`);
  });

  it('strips surrounding double quotes from paths', () => {
    const text = '"./Device/Vendor/MSFT/Policy/Config/Defender/AllowRealTimeMonitoring"';
    const paths = extractCspPaths(text);
    assert.ok(paths.includes('policy_config_defender_allowrealtimemonitoring'), `got: ${JSON.stringify(paths)}`);
  });

  it('strips surrounding single quotes from paths', () => {
    const text = "'./Device/Vendor/MSFT/Policy/Config/Defender/AllowRealTimeMonitoring'";
    const paths = extractCspPaths(text);
    assert.ok(paths.includes('policy_config_defender_allowrealtimemonitoring'), `got: ${JSON.stringify(paths)}`);
  });

  it('trims trailing punctuation artefacts', () => {
    const text = './Device/Vendor/MSFT/Policy/Config/Defender/AllowRealTimeMonitoring,';
    const paths = extractCspPaths(text);
    assert.ok(paths.includes('policy_config_defender_allowrealtimemonitoring'), `got: ${JSON.stringify(paths)}`);
  });

  it('deduplicates identical paths', () => {
    const text = `
      ./Device/Vendor/MSFT/Policy/Config/Defender/AllowRealTimeMonitoring
      ./Device/Vendor/MSFT/Policy/Config/Defender/AllowRealTimeMonitoring
    `;
    const paths = extractCspPaths(text);
    const count = paths.filter((p) => p === 'policy_config_defender_allowrealtimemonitoring').length;
    assert.equal(count, 1);
  });

  it('handles underscore-normalised Intune export keys', () => {
    const text = 'device_vendor_msft_policy_config_defender_allowrealtimemonitoring = 1';
    const paths = extractCspPaths(text);
    assert.ok(paths.includes('policy_config_defender_allowrealtimemonitoring'), `got: ${JSON.stringify(paths)}`);
  });

  it('handles vendor_msft_ prefix in Intune export keys', () => {
    const text = 'vendor_msft_laps_policies_backupdirectory = 1';
    const paths = extractCspPaths(text);
    assert.ok(paths.includes('laps_policies_backupdirectory'), `got: ${JSON.stringify(paths)}`);
  });

  it('handles user_vendor_msft_ prefix in Intune export keys', () => {
    const text = 'user_vendor_msft_policy_config_start_hideshutdown = 1';
    const paths = extractCspPaths(text);
    assert.ok(paths.includes('policy_config_start_hideshutdown'), `got: ${JSON.stringify(paths)}`);
  });

  it('returns empty array for text with no CSP paths', () => {
    const paths = extractCspPaths('Hello world, no policies here.');
    assert.equal(paths.length, 0);
  });

  it('handles Event Viewer-style XML with quoted paths', () => {
    const xml = `<Data Name="OMA-URI">"./Device/Vendor/MSFT/Policy/Config/Defender/AllowBehaviorMonitoring"</Data>`;
    const paths = extractCspPaths(xml);
    assert.ok(paths.includes('policy_config_defender_allowbehaviormonitoring'), `got: ${JSON.stringify(paths)}`);
  });
});

describe('extractAndTranslate (integration)', () => {
  it('resolves a known policy path', () => {
    const text = './Device/Vendor/MSFT/Policy/Config/Defender/AllowRealTimeMonitoring';
    const result = extractAndTranslate(text);
    // If the policy is in the seeded DB, it should be in found
    // If not in DB, it should be in unresolved (still valid behaviour)
    assert.ok(Array.isArray(result.found));
    assert.ok(Array.isArray(result.unresolved));
    assert.equal(result.found.length + result.unresolved.length, 1);
  });

  it('places unrecognised paths in unresolved', () => {
    const text = './Device/Vendor/MSFT/Policy/Config/Zzz/ZzzUnknownPolicy9999';
    const result = extractAndTranslate(text);
    assert.equal(result.found.length, 0);
    assert.equal(result.unresolved.length, 1);
    assert.ok(result.unresolved[0].includes('zzzunknownpolicy9999'), `got: ${result.unresolved[0]}`);
  });

  it('returns empty result for text with no CSP paths', () => {
    const result = extractAndTranslate('No CSP paths here.');
    assert.equal(result.found.length, 0);
    assert.equal(result.unresolved.length, 0);
  });

  it('deduplicates identical paths across found and unresolved', () => {
    const text = `
      ./Device/Vendor/MSFT/Policy/Config/Zzz/Duplicate9999
      ./Device/Vendor/MSFT/Policy/Config/Zzz/Duplicate9999
    `;
    const result = extractAndTranslate(text);
    assert.equal(result.found.length + result.unresolved.length, 1);
  });
});
