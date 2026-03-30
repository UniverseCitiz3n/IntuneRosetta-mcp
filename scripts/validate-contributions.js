#!/usr/bin/env node
'use strict';

/**
 * validate-contributions.js
 *
 * Validates all JSON files under db/contributions/ against the contribution
 * schema (db/contribution-schema.json) and checks for normalized_key
 * uniqueness and replaced_by_csp referential integrity.
 *
 * Environment variable overrides (for testing):
 *   CONTRIBUTIONS_DIR  – path to the contributions directory
 *   POLICIES_DB_PATH   – path to db/intune-policies.json
 *
 * Exit codes:
 *   0  – all files valid
 *   1  – one or more validation errors
 */

const Ajv = require('ajv');
const addFormats = require('ajv-formats');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

const contribDir =
  process.env['CONTRIBUTIONS_DIR'] || path.join(ROOT, 'db', 'contributions');

const policiesDbPath =
  process.env['POLICIES_DB_PATH'] || path.join(ROOT, 'db', 'intune-policies.json');

const schemaPath = path.join(ROOT, 'db', 'contribution-schema.json');

// ─── Load schema ─────────────────────────────────────────────────────────────

let schema;
try {
  schema = JSON.parse(fs.readFileSync(schemaPath, 'utf-8'));
} catch (err) {
  console.error(`Failed to load schema from ${schemaPath}: ${err.message}`);
  process.exit(1);
}

const ajv = new Ajv({ allErrors: true });
addFormats(ajv);
const validate = ajv.compile(schema);

// ─── Load existing normalized_keys from intune-policies.json ─────────────────

/** @type {Set<string>} */
const existingKeys = new Set();

if (fs.existsSync(policiesDbPath)) {
  try {
    const db = JSON.parse(fs.readFileSync(policiesDbPath, 'utf-8'));
    const records = db.records || [];
    for (const r of records) {
      if (typeof r.normalized_key === 'string') {
        existingKeys.add(r.normalized_key);
      }
    }
  } catch (err) {
    console.error(`Warning: could not parse ${policiesDbPath}: ${err.message}`);
  }
}

// ─── Discover contribution files ─────────────────────────────────────────────

if (!fs.existsSync(contribDir)) {
  console.log('No contributions directory found. Nothing to validate.');
  process.exit(0);
}

const files = fs
  .readdirSync(contribDir)
  .filter((f) => f.endsWith('.json') && f !== '.gitkeep')
  .sort();

if (files.length === 0) {
  console.log('No contribution files found. Nothing to validate.');
  process.exit(0);
}

// ─── Pass 1: parse files and collect all contribution keys ───────────────────

/**
 * @type {Array<{ file: string, data: any[] }>}
 */
const parsed = [];

/** @type {Map<string, string>} normalized_key → source filename */
const contribKeys = new Map();

/** @type {string[]} */
const errors = [];

for (const file of files) {
  const filePath = path.join(contribDir, file);
  let data;

  try {
    data = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  } catch (err) {
    errors.push(`[${file}] JSON parse error: ${err.message}`);
    continue;
  }

  if (!Array.isArray(data)) {
    errors.push(`[${file}] Top-level value must be a JSON array.`);
    continue;
  }

  parsed.push({ file, data });

  for (const record of data) {
    if (typeof record.normalized_key !== 'string') continue;
    const key = record.normalized_key;

    if (contribKeys.has(key)) {
      errors.push(
        `[${file}] Duplicate normalized_key '${key}' (already seen in '${contribKeys.get(key)}').`,
      );
    } else if (existingKeys.has(key)) {
      errors.push(
        `[${file}] normalized_key '${key}' already exists in db/intune-policies.json.`,
      );
    } else {
      contribKeys.set(key, file);
    }
  }
}

// ─── Pass 2: schema validation + replaced_by_csp integrity ───────────────────

// Full set of all known keys after contributions
const allKeys = new Set([...existingKeys, ...contribKeys.keys()]);

for (const { file, data } of parsed) {
  // Schema validation
  const valid = validate(data);
  if (!valid && validate.errors) {
    for (const err of validate.errors) {
      const location = err.instancePath || '(root)';
      errors.push(`[${file}] Schema error at ${location}: ${err.message}`);
    }
  }

  // Referential integrity: replaced_by_csp must resolve to a known key
  for (const record of data) {
    if (record.replaced_by_csp && typeof record.replaced_by_csp === 'string') {
      if (!allKeys.has(record.replaced_by_csp)) {
        errors.push(
          `[${file}] replaced_by_csp '${record.replaced_by_csp}' on key '${record.normalized_key}' ` +
            `is not found in db/intune-policies.json or any contribution file.`,
        );
      }
    }
  }
}

// ─── Report ──────────────────────────────────────────────────────────────────

if (errors.length > 0) {
  console.error(`\n✗ Contribution validation failed with ${errors.length} error(s):\n`);
  for (const err of errors) {
    console.error(`  ${err}`);
  }
  process.exit(1);
} else {
  const totalRecords = parsed.reduce((n, { data }) => n + data.length, 0);
  console.log(
    `✓ All ${files.length} contribution file(s) (${totalRecords} record(s)) validated successfully.`,
  );
  process.exit(0);
}

module.exports = { validate, existingKeys };
