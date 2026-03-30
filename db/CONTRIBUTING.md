# Contributing to the IntuneRosetta Knowledge Base

IntuneRosetta ships with a pre-built KB (`db/intune-policies.json`) containing
thousands of Intune / OMA-URI policy records.  If you know of a policy that is
missing or incorrect, you can contribute it via a **contribution file** in
`db/contributions/`.

---

## Quick start

1. **Copy the template**

   ```bash
   cp db/contribution-template.json db/contributions/my-policies.json
   ```

2. **Fill in your records** — see [Field definitions](#field-definitions) below.

3. **Validate locally** (requires `npm ci` first):

   ```bash
   node scripts/validate-contributions.js
   ```

4. **Open a PR** targeting `main`.  The [CI workflow](.github/workflows/validate-contributions.yml)
   will automatically validate your contribution file on every push.

---

## File format

A contribution file is a **JSON array** of policy record objects.  Each element
must conform to [`db/contribution-schema.json`](contribution-schema.json).

```json
[
  {
    "normalized_key": "policy_config_defender_allowcloudprotection",
    "name": "Defender: Allow cloud-delivered protection",
    "description": "Enables cloud-delivered protection in Microsoft Defender Antivirus.",
    "csp_path": "./Device/Vendor/MSFT/Policy/Config/Defender/AllowCloudProtection",
    "category": "Defender",
    "docs_url": "https://learn.microsoft.com/...",
    "value_map": { "0": "Disabled", "1": "Enabled" }
  }
]
```

---

## Field definitions

| Field | Required | Description |
|---|---|---|
| `normalized_key` | ✅ | Unique underscore-delimited identifier.  Lowercase, only `[a-z0-9_]`, **no** `device_vendor_msft_` prefix.  Example: `policy_config_defender_allowcloudprotection` |
| `name` | ✅ | Human-readable policy name (≥ 3 characters). |
| `csp_path` | ✅ | Canonical OMA-URI path.  Must start with `./Device/Vendor/MSFT/` or `./User/Vendor/MSFT/`. |
| `category` | ✅ | Policy area (e.g. `Defender ASR`, `BitLocker`, `LAPS`).  Use an existing category name when possible to keep grouping consistent. |
| `description` | optional | Human-readable explanation of what the policy controls. |
| `docs_url` | optional | Link to the official Microsoft documentation page. |
| `value_map` | optional | Object mapping raw integer/string values to human-readable labels.  Example: `{ "0": "Disabled", "1": "Block", "2": "Audit" }` |
| `is_deprecated` | optional | Set to `true` when this policy has been superseded.  Defaults to `false`. |
| `replaced_by_csp` | optional | `normalized_key` of the replacement record.  **Must reference a key that exists** in `db/intune-policies.json` or another contribution file in the same PR. |
| `deprecation_notice` | optional | Free-text explanation: why deprecated, since when, migration guidance. |

### `normalized_key` rules

* Must match `^[a-z0-9_]+$` — no uppercase, no hyphens, no spaces.
* Must be **globally unique** across `db/intune-policies.json` and all contribution files.
* Do **not** include the `device_vendor_msft_` prefix (it is stripped during normalisation).
* Derive it from the OMA-URI path: strip `./Device/Vendor/MSFT/`, replace `/` with `_`, lowercase everything.

  Example:
  ```
  ./Device/Vendor/MSFT/Policy/Config/Defender/AllowCloudProtection
  → policy_config_defender_allowcloudprotection
  ```

### Deprecation pattern

When a policy is superseded, mark the old record with `is_deprecated: true` and
point `replaced_by_csp` at the `normalized_key` of the new record:

```json
{
  "normalized_key": "policy_config_defender_oldpolicy",
  "name": "Old Policy Name (Deprecated)",
  "csp_path": "./Device/Vendor/MSFT/Policy/Config/Defender/OldPolicy",
  "category": "Defender",
  "is_deprecated": true,
  "replaced_by_csp": "policy_config_defender_newpolicy",
  "deprecation_notice": "Superseded by NewPolicy in Intune Settings Catalogue Q4 2024."
}
```

The server will attach a `deprecation_warning` field to any response that
returns a deprecated record, so users are alerted automatically.

---

## Validation rules

The CI workflow (`validate-contributions.yml`) enforces:

1. **Schema conformance** — every record matches `db/contribution-schema.json`.
2. **`normalized_key` uniqueness** — no key appears in more than one contribution
   file, and no key conflicts with an existing record in `db/intune-policies.json`.
3. **`replaced_by_csp` integrity** — if set, the referenced key must exist in
   `db/intune-policies.json` or in another contribution file in the same PR.

Run the validator locally before opening your PR:

```bash
npm ci
node scripts/validate-contributions.js
```

---

## Where do contribution files go?

Place your `.json` file(s) in the `db/contributions/` directory and open a PR.
The file name can be anything descriptive, e.g. `windows-firewall-policies.json`
or `my-org-custom-csp.json`.

The maintainers will review, merge, and periodically incorporate accepted
contributions into the main `db/intune-policies.json` KB.
