import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';

const REPO_ROOT = path.join(__dirname, '..', '..');
const SCRIPT = path.join(REPO_ROOT, 'scripts', 'validate-contributions.js');
const POLICIES_DB = path.join(REPO_ROOT, 'db', 'intune-policies.json');

/** Run the validator script against a temporary contributions directory. */
function runValidator(contribDir: string): { status: number; stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, [SCRIPT], {
    encoding: 'utf-8',
    env: {
      ...process.env,
      CONTRIBUTIONS_DIR: contribDir,
      POLICIES_DB_PATH: POLICIES_DB,
    },
  });
  return {
    status: result.status ?? 1,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

/** Create a temp directory and write files into it. Returns the dir path. */
function makeTempDir(files: Record<string, unknown>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'intune-contrib-test-'));
  for (const [name, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, name), JSON.stringify(content, null, 2), 'utf-8');
  }
  return dir;
}

const tempDirs: string[] = [];

after(() => {
  for (const dir of tempDirs) {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
  }
});

describe('validate-contributions.js', () => {
  it('exits 0 when the contributions directory does not exist', () => {
    const result = runValidator('/tmp/nonexistent-dir-xyzxyz');
    assert.equal(result.status, 0);
    assert.ok(result.stdout.includes('No contributions directory'));
  });

  it('exits 0 when there are no .json files', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'intune-contrib-empty-'));
    tempDirs.push(dir);
    const result = runValidator(dir);
    assert.equal(result.status, 0);
  });

  it('exits 0 for a valid contribution file', () => {
    const dir = makeTempDir({
      'valid.json': [
        {
          normalized_key: 'test_zzz_valid_policy_9999',
          name: 'Test Valid Policy 9999',
          csp_path: './Device/Vendor/MSFT/Policy/Config/Test/ValidPolicy9999',
          category: 'Test',
          description: 'A test policy.',
        },
      ],
    });
    tempDirs.push(dir);
    const result = runValidator(dir);
    assert.equal(result.status, 0, `stderr: ${result.stderr}\nstdout: ${result.stdout}`);
    assert.ok(result.stdout.includes('validated successfully'));
  });

  it('exits 1 when normalized_key is missing a required field', () => {
    const dir = makeTempDir({
      'missing-field.json': [
        {
          // missing normalized_key
          name: 'Missing Key Policy',
          csp_path: './Device/Vendor/MSFT/Policy/Config/Test/MissingKey',
          category: 'Test',
        },
      ],
    });
    tempDirs.push(dir);
    const result = runValidator(dir);
    assert.equal(result.status, 1);
  });

  it('exits 1 when normalized_key has invalid characters', () => {
    const dir = makeTempDir({
      'bad-key.json': [
        {
          normalized_key: 'INVALID-KEY-WITH-UPPERCASE',
          name: 'Bad Key Policy',
          csp_path: './Device/Vendor/MSFT/Policy/Config/Test/BadKey',
          category: 'Test',
        },
      ],
    });
    tempDirs.push(dir);
    const result = runValidator(dir);
    assert.equal(result.status, 1);
  });

  it('exits 1 when csp_path does not start with ./Device/ or ./User/', () => {
    const dir = makeTempDir({
      'bad-path.json': [
        {
          normalized_key: 'test_zzz_bad_path_9999',
          name: 'Bad Path Policy',
          csp_path: '/Device/Vendor/MSFT/Policy/Config/Test/BadPath',
          category: 'Test',
        },
      ],
    });
    tempDirs.push(dir);
    const result = runValidator(dir);
    assert.equal(result.status, 1);
  });

  it('exits 1 when the file is not a JSON array', () => {
    const dir = makeTempDir({
      'not-array.json': {
        normalized_key: 'test_zzz_not_array',
        name: 'Not an array',
        csp_path: './Device/Vendor/MSFT/Policy/Config/Test/NotArray',
        category: 'Test',
      },
    });
    tempDirs.push(dir);
    const result = runValidator(dir);
    assert.equal(result.status, 1);
  });

  it('exits 1 for duplicate normalized_key within the same file', () => {
    const record = {
      normalized_key: 'test_zzz_duplicate_9999',
      name: 'Duplicate Policy',
      csp_path: './Device/Vendor/MSFT/Policy/Config/Test/Duplicate9999',
      category: 'Test',
    };
    const dir = makeTempDir({
      'dupes.json': [record, record],
    });
    tempDirs.push(dir);
    const result = runValidator(dir);
    assert.equal(result.status, 1);
    assert.ok(
      result.stderr.includes('Duplicate'),
      `expected 'Duplicate' in stderr, got: ${result.stderr}`,
    );
  });

  it('exits 1 for duplicate normalized_key across two contribution files', () => {
    const dir = makeTempDir({
      'file-a.json': [
        {
          normalized_key: 'test_zzz_crossfile_9999',
          name: 'Cross-File Duplicate A',
          csp_path: './Device/Vendor/MSFT/Policy/Config/Test/CrossFileDup',
          category: 'Test',
        },
      ],
      'file-b.json': [
        {
          normalized_key: 'test_zzz_crossfile_9999',
          name: 'Cross-File Duplicate B',
          csp_path: './Device/Vendor/MSFT/Policy/Config/Test/CrossFileDup',
          category: 'Test',
        },
      ],
    });
    tempDirs.push(dir);
    const result = runValidator(dir);
    assert.equal(result.status, 1);
  });

  it('exits 1 when replaced_by_csp references a nonexistent key', () => {
    const dir = makeTempDir({
      'deprecated.json': [
        {
          normalized_key: 'test_zzz_deprecated_9999',
          name: 'Deprecated Policy',
          csp_path: './Device/Vendor/MSFT/Policy/Config/Test/Deprecated9999',
          category: 'Test',
          is_deprecated: true,
          replaced_by_csp: 'test_zzz_nonexistent_replacement_9999',
          deprecation_notice: 'This is deprecated.',
        },
      ],
    });
    tempDirs.push(dir);
    const result = runValidator(dir);
    assert.equal(result.status, 1);
    assert.ok(
      result.stderr.includes('replaced_by_csp'),
      `expected 'replaced_by_csp' in stderr, got: ${result.stderr}`,
    );
  });

  it('exits 0 when replaced_by_csp references a key in another contribution file', () => {
    const dir = makeTempDir({
      'new-policy.json': [
        {
          normalized_key: 'test_zzz_new_policy_9999',
          name: 'New Policy 9999',
          csp_path: './Device/Vendor/MSFT/Policy/Config/Test/NewPolicy9999',
          category: 'Test',
        },
      ],
      'deprecated-policy.json': [
        {
          normalized_key: 'test_zzz_deprecated_for_new_9999',
          name: 'Old Policy 9999',
          csp_path: './Device/Vendor/MSFT/Policy/Config/Test/OldPolicy9999',
          category: 'Test',
          is_deprecated: true,
          replaced_by_csp: 'test_zzz_new_policy_9999',
          deprecation_notice: 'Replaced by test_zzz_new_policy_9999.',
        },
      ],
    });
    tempDirs.push(dir);
    const result = runValidator(dir);
    assert.equal(result.status, 0, `stderr: ${result.stderr}\nstdout: ${result.stdout}`);
  });

  it('exits 1 for invalid JSON', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'intune-contrib-badjson-'));
    tempDirs.push(dir);
    fs.writeFileSync(path.join(dir, 'bad.json'), '{ not valid json ]', 'utf-8');
    const result = runValidator(dir);
    assert.equal(result.status, 1);
  });
});
