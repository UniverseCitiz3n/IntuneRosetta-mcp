import { describe, it, mock, before } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import {
  graphPathToNormalizedKey,
  graphApiResultToRecord,
  buildKnowledgeBase,
  KB_SEARCH_TERMS,
} from '../kb-builder';
import { MsgraphKbClient, GraphApiResult } from '../msgraph-client';
import { findByKey, seedDatabase, closeDb } from '../db';

// Use a fresh DB for this suite
before(() => {
  closeDb();
  process.env['INTUNE_ROSETTA_DB_PATH'] = path.join(os.tmpdir(), `test_kbbuilder_${Date.now()}.db`);
  seedDatabase();
});

// ── graphPathToNormalizedKey ─────────────────────────────────────────────────
describe('graphPathToNormalizedKey', () => {
  it('converts a simple path', () => {
    assert.equal(
      graphPathToNormalizedKey('/deviceManagement/configurationSettings'),
      'devicemanagement_configurationsettings',
    );
  });

  it('strips path parameters', () => {
    assert.equal(
      graphPathToNormalizedKey('/deviceManagement/managedDevices/{managedDevice-id}/rotateLocalAdminPassword'),
      'devicemanagement_manageddevices_rotatelocaladminpassword',
    );
  });

  it('collapses consecutive underscores produced by stripped params', () => {
    const key = graphPathToNormalizedKey('/deviceManagement/{id}/foo');
    assert.ok(!key.includes('__'), `should not contain double underscore, got: ${key}`);
  });

  it('strips trailing underscores', () => {
    const key = graphPathToNormalizedKey('/deviceManagement/foo/{id}');
    assert.ok(!key.endsWith('_'), `should not end with underscore, got: ${key}`);
  });

  it('lowercases the result', () => {
    assert.equal(
      graphPathToNormalizedKey('/DeviceManagement/ConfigurationSettings'),
      'devicemanagement_configurationsettings',
    );
  });
});

// ── graphApiResultToRecord ───────────────────────────────────────────────────
describe('graphApiResultToRecord', () => {
  it('maps a result with description', () => {
    const result: GraphApiResult = {
      path: '/deviceManagement/configurationSettings',
      method: 'GET',
      summary: 'Get configurationSettings',
      description: 'List of all ConfigurationSettings for device management.',
    };
    const record = graphApiResultToRecord(result);
    assert.equal(record.normalized_key, 'devicemanagement_configurationsettings');
    assert.equal(record.name, 'List of all ConfigurationSettings for device management.');
    assert.equal(record.description, 'List of all ConfigurationSettings for device management.');
    assert.equal(record.csp_path, '/deviceManagement/configurationSettings');
    assert.ok(record.docs_url.startsWith('https://learn.microsoft.com/'));
    assert.equal(record.value_map, '{}');
  });

  it('falls back to summary when description is missing', () => {
    const result: GraphApiResult = {
      path: '/deviceManagement/foo',
      method: 'GET',
      summary: 'Foo summary',
    };
    const record = graphApiResultToRecord(result);
    // When description is absent, summary is used for both name and description
    assert.equal(record.name, 'Foo summary');
    assert.equal(record.description, 'Foo summary');
  });

  it('falls back to summary when description is too long (≥120 chars)', () => {
    const longDesc = 'a'.repeat(120);
    const result: GraphApiResult = {
      path: '/deviceManagement/bar',
      method: 'GET',
      summary: 'Short summary',
      description: longDesc,
    };
    const record = graphApiResultToRecord(result);
    assert.equal(record.name, 'Short summary');
  });

  it('infers BitLocker category from path', () => {
    const result: GraphApiResult = {
      path: '/deviceManagement/managedDeviceEncryptionStates',
      method: 'GET',
      summary: 'Encryption states',
    };
    const record = graphApiResultToRecord(result);
    assert.equal(record.category, 'BitLocker');
  });

  it('infers LAPS category from path containing localadmin', () => {
    const result: GraphApiResult = {
      path: '/deviceManagement/managedDevices/{id}/rotateLocalAdminPassword',
      method: 'POST',
      summary: 'Rotate local admin password',
    };
    const record = graphApiResultToRecord(result);
    assert.equal(record.category, 'LAPS');
  });

  it('infers Defender category', () => {
    const result: GraphApiResult = {
      path: '/deviceManagement/managedDevices/{id}/windowsDefenderScan',
      method: 'POST',
      summary: 'Windows Defender scan',
    };
    const record = graphApiResultToRecord(result);
    assert.equal(record.category, 'Defender');
  });
});

// ── KB_SEARCH_TERMS ──────────────────────────────────────────────────────────
describe('KB_SEARCH_TERMS', () => {
  it('is a non-empty array of strings', () => {
    assert.ok(Array.isArray(KB_SEARCH_TERMS));
    assert.ok(KB_SEARCH_TERMS.length > 0);
    for (const term of KB_SEARCH_TERMS) {
      assert.equal(typeof term, 'string');
      assert.ok(term.length > 0);
    }
  });

  it('covers at least 15 distinct policy areas', () => {
    assert.ok(KB_SEARCH_TERMS.length >= 15);
  });
});

// ── buildKnowledgeBase ───────────────────────────────────────────────────────
describe('buildKnowledgeBase', () => {
  it('returns zero stats when client is not configured', async () => {
    const unconfiguredClient = new MsgraphKbClient();
    // MSGRAPH_KB_COMMAND is not set in test env
    const stats = await buildKnowledgeBase(unconfiguredClient);
    assert.equal(stats.terms_searched, 0);
    assert.equal(stats.results_found, 0);
    assert.equal(stats.records_upserted, 0);
    assert.equal(stats.errors, 0);
  });

  it('searches all KB_SEARCH_TERMS and upserts results', async () => {
    const fakeResults: GraphApiResult[] = [
      {
        path: '/deviceManagement/configurationSettings',
        method: 'GET',
        summary: 'Get configuration settings',
        description: 'List of all ConfigurationSettings.',
      },
      {
        path: '/deviceManagement/deviceConfigurations',
        method: 'GET',
        summary: 'Get device configurations',
        description: 'Device configuration policies.',
      },
    ];

    const mockClient = {
      isConfigured: () => true,
      searchGraphApis: mock.fn(async () => fakeResults),
    } as unknown as MsgraphKbClient;

    const stats = await buildKnowledgeBase(mockClient);

    assert.equal(stats.terms_searched, KB_SEARCH_TERMS.length);
    // Results are the same 2 paths for every term, but deduplication means only 2 upserted
    assert.equal(stats.results_found, KB_SEARCH_TERMS.length * fakeResults.length);
    assert.equal(stats.records_upserted, 2);
    assert.equal(stats.errors, 0);

    // Verify records were persisted
    const r1 = findByKey('devicemanagement_configurationsettings');
    assert.ok(r1 !== undefined);
    assert.equal(r1!.description, 'List of all ConfigurationSettings.');

    const r2 = findByKey('devicemanagement_deviceconfigurations');
    assert.ok(r2 !== undefined);
  });

  it('deduplicates results that appear across multiple search terms', async () => {
    const sameResult: GraphApiResult[] = [
      {
        path: '/deviceManagement/dedupeTest',
        method: 'GET',
        summary: 'Dedupe test',
        description: 'Appears in every search term result.',
      },
    ];

    const mockClient = {
      isConfigured: () => true,
      searchGraphApis: mock.fn(async () => sameResult),
    } as unknown as MsgraphKbClient;

    const stats = await buildKnowledgeBase(mockClient, true);

    // Even though it appears once per term, it should only be upserted once
    assert.equal(stats.records_upserted, 1);
  });

  it('skips existing records when force=false', async () => {
    // Seed a record first
    const { upsertPolicy } = await import('../db');
    upsertPolicy({
      normalized_key: 'devicemanagement_forcetest',
      name: 'Original Name',
      description: 'Original',
      csp_path: '/deviceManagement/forceTest',
      category: 'Intune',
      docs_url: '',
      value_map: '{}',
    });

    const updatedResult: GraphApiResult[] = [
      {
        path: '/deviceManagement/forceTest',
        method: 'GET',
        summary: 'Updated Name',
        description: 'Updated description.',
      },
    ];

    const mockClient = {
      isConfigured: () => true,
      searchGraphApis: mock.fn(async () => updatedResult),
    } as unknown as MsgraphKbClient;

    // force=false — should skip existing
    await buildKnowledgeBase(mockClient, false);
    const record = findByKey('devicemanagement_forcetest');
    assert.equal(record!.name, 'Original Name');

    // force=true — should overwrite
    await buildKnowledgeBase(mockClient, true);
    const updatedRecord = findByKey('devicemanagement_forcetest');
    assert.equal(updatedRecord!.name, 'Updated description.');
  });

  it('counts errors and continues when searchGraphApis throws', async () => {
    let callCount = 0;
    const mockClient = {
      isConfigured: () => true,
      searchGraphApis: mock.fn(async () => {
        callCount++;
        if (callCount % 2 === 0) throw new Error('network error');
        return [] as GraphApiResult[];
      }),
    } as unknown as MsgraphKbClient;

    const stats = await buildKnowledgeBase(mockClient);

    assert.equal(stats.terms_searched, KB_SEARCH_TERMS.length);
    assert.ok(stats.errors > 0);
    // Should have processed all terms despite errors
    assert.equal(stats.errors, Math.floor(KB_SEARCH_TERMS.length / 2));
  });
});
