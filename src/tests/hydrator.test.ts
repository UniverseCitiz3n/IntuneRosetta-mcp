import { describe, it, mock, before } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { extractSearchKeywords, hydrateFromMsgraphKb, hydratePolicyRecord } from '../hydrator';
import { MsgraphKbClient, GraphApiResult } from '../msgraph-client';
import { findByKey, seedDatabase, closeDb } from '../db';

// Use a stable path for the non-hydrateFromMsgraphKb tests
process.env['INTUNE_ROSETTA_DB_PATH'] = path.join(os.tmpdir(), 'test_hydrator_intune.db');
seedDatabase();

// ── extractSearchKeywords ────────────────────────────────────────────────────
describe('extractSearchKeywords', () => {
  it('strips policy_config_ prefix', () => {
    const kw = extractSearchKeywords('policy_config_defender_attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts');
    assert.ok(kw.includes('defender'));
    assert.ok(kw.includes('attacksurfacereductionrules'));
  });

  it('strips policy_config_ and value suffix', () => {
    const kw = extractSearchKeywords('policy_config_bitlocker_requiredeviceencryption_1');
    assert.ok(kw.includes('bitlocker'));
    assert.ok(!kw.includes('_1'));
  });

  it('handles laps prefix', () => {
    const kw = extractSearchKeywords('laps_policies_backupdirectory');
    assert.ok(kw.toLowerCase().includes('laps'));
    assert.ok(kw.toLowerCase().includes('backupdirectory'));
  });

  it('replaces underscores with spaces', () => {
    const kw = extractSearchKeywords('policy_config_smartscreen_enablesmartscreeninshell');
    assert.ok(!kw.includes('_'));
  });
});

// ── hydratePolicyRecord ──────────────────────────────────────────────────────
describe('hydratePolicyRecord', () => {
  it('stores a record in the database', () => {
    hydratePolicyRecord({
      normalized_key: 'test_hydrate_policy_123',
      name: 'Test Hydrated Policy',
      description: 'A test policy inserted via hydratePolicyRecord',
      csp_path: './Device/Vendor/MSFT/Test/Hydrate/Policy',
      category: 'Test',
      docs_url: 'https://example.com/docs',
      value_map: JSON.stringify({ '0': 'Off', '1': 'On' }),
    });

    const found = findByKey('test_hydrate_policy_123');
    assert.ok(found !== undefined);
    assert.equal(found!.name, 'Test Hydrated Policy');
    assert.equal(found!.category, 'Test');
  });

  it('overwrites an existing record on conflict', () => {
    hydratePolicyRecord({
      normalized_key: 'test_hydrate_policy_123',
      name: 'Updated Hydrated Policy',
      description: 'Updated description',
      csp_path: './Device/Vendor/MSFT/Test/Hydrate/Policy',
      category: 'Test',
      docs_url: 'https://example.com/docs-v2',
      value_map: '{}',
    });

    const found = findByKey('test_hydrate_policy_123');
    assert.equal(found!.name, 'Updated Hydrated Policy');
    assert.equal(found!.docs_url, 'https://example.com/docs-v2');
  });
});

// ── hydrateFromMsgraphKb ─────────────────────────────────────────────────────
describe('hydrateFromMsgraphKb', () => {
  before(() => {
    // Use a fresh DB for this suite to avoid key collisions from previous runs
    closeDb();
    process.env['INTUNE_ROSETTA_DB_PATH'] = path.join(os.tmpdir(), `test_hydrator_${Date.now()}.db`);
    seedDatabase();
  });
  it('returns undefined when client is not configured', async () => {
    const client = new MsgraphKbClient();
    // MSGRAPH_KB_COMMAND is not set in test env
    const result = await hydrateFromMsgraphKb(client, 'device_vendor_msft_policy_config_privacy_letappsaccesscamera');
    assert.equal(result, undefined);
  });

  it('returns undefined when key already exists in DB', async () => {
    // defender_allowrealtimemonitoring is seeded
    const mockClient = {
      isConfigured: () => true,
      searchGraphApis: mock.fn(async () => [] as GraphApiResult[]),
    } as unknown as MsgraphKbClient;

    const result = await hydrateFromMsgraphKb(mockClient, 'device_vendor_msft_policy_config_defender_allowrealtimemonitoring');
    assert.equal(result, undefined);
  });

  it('stores and returns a record when msgraph-kb returns results', async () => {
    const fakeResults: GraphApiResult[] = [
      {
        path: '/deviceManagement/deviceConfigurations',
        method: 'GET',
        summary: 'Get device configurations',
        description: 'Returns a list of all device configuration policies.',
        availability: 'beta',
      },
    ];

    const mockClient = {
      isConfigured: () => true,
      searchGraphApis: mock.fn(async () => fakeResults),
    } as unknown as MsgraphKbClient;

    const uniqueKey = 'device_vendor_msft_policy_config_testhydrate_uniquepolicy_99';
    const result = await hydrateFromMsgraphKb(mockClient, uniqueKey);

    assert.ok(result !== undefined);
    assert.equal(result!.description, 'Returns a list of all device configuration policies.');
    assert.ok(result!.docs_url.startsWith('https://learn.microsoft.com/'));

    // Verify persisted (value suffix _99 is stripped, so key is without it)
    const stored = findByKey('policy_config_testhydrate_uniquepolicy');
    assert.ok(stored !== undefined);
    assert.equal(stored!.description, 'Returns a list of all device configuration policies.');
  });

  it('prefers result with non-empty description over first result', async () => {
    const fakeResults: GraphApiResult[] = [
      {
        path: '/deviceManagement/foo',
        method: 'GET',
        summary: 'Foo summary',
        // no description
      },
      {
        path: '/deviceManagement/bar',
        method: 'GET',
        summary: 'Bar summary',
        description: 'This is the better description.',
      },
    ];

    const mockClient = {
      isConfigured: () => true,
      searchGraphApis: mock.fn(async () => fakeResults),
    } as unknown as MsgraphKbClient;

    const uniqueKey2 = 'device_vendor_msft_policy_config_testhydrate_preferdescription_7';
    const result = await hydrateFromMsgraphKb(mockClient, uniqueKey2);

    assert.ok(result !== undefined);
    assert.equal(result!.description, 'This is the better description.');
  });

  it('returns undefined when msgraph-kb returns empty results', async () => {
    const mockClient = {
      isConfigured: () => true,
      searchGraphApis: mock.fn(async () => [] as GraphApiResult[]),
    } as unknown as MsgraphKbClient;

    const result = await hydrateFromMsgraphKb(mockClient, 'device_vendor_msft_policy_config_testhydrate_noresults_0');
    assert.equal(result, undefined);
  });

  it('returns undefined and does not throw when msgraph-kb throws', async () => {
    const mockClient = {
      isConfigured: () => true,
      searchGraphApis: mock.fn(async () => { throw new Error('connection refused'); }),
    } as unknown as MsgraphKbClient;

    const result = await hydrateFromMsgraphKb(mockClient, 'device_vendor_msft_policy_config_testhydrate_error_1');
    assert.equal(result, undefined);
  });
});
