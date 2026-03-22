import Database from 'better-sqlite3';
import path from 'path';
import os from 'os';
import fs from 'fs';
import { PolicyRecord, ValueMap } from './types';

function getDbPath(): string {
  if (process.env['INTUNE_ROSETTA_DB_PATH']) {
    return process.env['INTUNE_ROSETTA_DB_PATH'];
  }
  // Default to the user's home directory data folder for a predictable, writable location
  const dataDir = path.join(os.homedir(), '.intunerosetta');
  return path.join(dataDir, 'intune_rosetta.db');
}

let db: Database.Database | undefined;

export function getDb(): Database.Database {
  if (!db) {
    const dbPath = getDbPath();
    // Ensure the parent directory exists
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
    db = new Database(dbPath);
    db.pragma('journal_mode = WAL');
    initSchema();
  }
  return db;
}

/**
 * Close the current database connection and clear the singleton.
 * Intended for use in tests to allow re-initialization with a different path.
 */
export function closeDb(): void {
  if (db) {
    db.close();
    db = undefined;
  }
}

function initSchema(): void {
  const database = getDb();
  database.exec(`
    CREATE TABLE IF NOT EXISTS policies (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      normalized_key TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      csp_path TEXT NOT NULL,
      category TEXT NOT NULL DEFAULT '',
      docs_url TEXT NOT NULL DEFAULT '',
      value_map TEXT NOT NULL DEFAULT '{}'
    );
    CREATE INDEX IF NOT EXISTS idx_policies_name ON policies(name COLLATE NOCASE);
    CREATE INDEX IF NOT EXISTS idx_policies_category ON policies(category);
  `);
}

export function upsertPolicy(record: Omit<PolicyRecord, 'id'>): void {
  const database = getDb();
  const stmt = database.prepare(`
    INSERT INTO policies (normalized_key, name, description, csp_path, category, docs_url, value_map)
    VALUES (@normalized_key, @name, @description, @csp_path, @category, @docs_url, @value_map)
    ON CONFLICT(normalized_key) DO UPDATE SET
      name = excluded.name,
      description = excluded.description,
      csp_path = excluded.csp_path,
      category = excluded.category,
      docs_url = excluded.docs_url,
      value_map = excluded.value_map
  `);
  stmt.run(record);
}

export function findByKey(normalizedKey: string): PolicyRecord | undefined {
  const database = getDb();
  return database.prepare(
    'SELECT * FROM policies WHERE normalized_key = ?'
  ).get(normalizedKey) as PolicyRecord | undefined;
}

export function searchPolicies(query: string, limit = 20): PolicyRecord[] {
  const database = getDb();
  const pattern = `%${query.toLowerCase()}%`;
  return database.prepare(`
    SELECT * FROM policies
    WHERE LOWER(name) LIKE ?
       OR LOWER(description) LIKE ?
       OR LOWER(normalized_key) LIKE ?
       OR LOWER(category) LIKE ?
    LIMIT ?
  `).all(pattern, pattern, pattern, pattern, limit) as PolicyRecord[];
}

export function findByCspPathFragment(fragment: string, limit = 20): PolicyRecord[] {
  const database = getDb();
  const pattern = `%${fragment.toLowerCase()}%`;
  return database.prepare(`
    SELECT * FROM policies
    WHERE LOWER(csp_path) LIKE ?
       OR LOWER(name) LIKE ?
    LIMIT ?
  `).all(pattern, pattern, limit) as PolicyRecord[];
}

/**
 * Load the pre-built Intune policy knowledge base from `db/intune-policies.json`.
 *
 * This JSON file was built at development time by querying the Microsoft Graph API
 * (via Lokka and msgraph-kb MCP tools) and is committed to the repository so the
 * server starts with a fully populated KB — no runtime Graph API connection required.
 */
function loadPrebuiltKb(): Array<Omit<PolicyRecord, 'id'>> {
  // Works from dist/ (compiled) or src/ (ts-node): resolve relative to this file's dir
  const candidates = [
    path.join(__dirname, '..', 'db', 'intune-policies.json'),
    path.join(__dirname, '..', '..', 'db', 'intune-policies.json'),
  ];
  for (const p of candidates) {
    if (fs.existsSync(p)) {
      try {
        const raw = fs.readFileSync(p, 'utf-8');
        const parsed = JSON.parse(raw) as { records: Array<Omit<PolicyRecord, 'id'>> };
        return parsed.records ?? [];
      } catch (err) {
        // JSON parse / file-read error for this candidate — try the next path
        process.stderr?.write?.(`[IntuneRosetta] Warning: failed to load ${p}: ${err}\n`);
      }
    }
  }
  return [];
}

export function seedDatabase(): void {
  const database = getDb();
  const count = (database.prepare('SELECT COUNT(*) as c FROM policies').get() as { c: number }).c;
  if (count > 0) return;

  // Load the pre-built KB data (built from Microsoft Graph API via Lokka/msgraph-kb)
  const kbData = loadPrebuiltKb();

  // Built-in hand-curated seed data — these take precedence over the pre-built KB
  // because they carry precise names, full descriptions and detailed value maps.
  const seedData: Array<Omit<PolicyRecord, 'id'>> = [
    // ─── Defender ASR Rules ───────────────────────────────────────────────────
    {
      normalized_key: 'policy_config_defender_attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts',
      name: 'ASR: Block execution of potentially obfuscated scripts',
      description: 'Blocks scripts that appear to be obfuscated to evade detection. Requires Windows Defender Antivirus.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules',
      category: 'Defender ASR',
      docs_url: 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference#block-execution-of-potentially-obfuscated-scripts',
      value_map: JSON.stringify({ '0': 'Disabled', '1': 'Block', '2': 'Audit', '6': 'Warn' } as ValueMap),
    },
    {
      normalized_key: 'policy_config_defender_attacksurfacereductionrules_blockwin32apicallsfromofficemacros',
      name: 'ASR: Block Win32 API calls from Office macros',
      description: 'Prevents Office macros from calling Win32 APIs, which can be used to execute malicious code.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules',
      category: 'Defender ASR',
      docs_url: 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference#block-win32-api-calls-from-office-macros',
      value_map: JSON.stringify({ '0': 'Disabled', '1': 'Block', '2': 'Audit', '6': 'Warn' } as ValueMap),
    },
    {
      normalized_key: 'policy_config_defender_attacksurfacereductionrules_blockofficeapplicationsfromcreatingchildprocesses',
      name: 'ASR: Block Office applications from creating child processes',
      description: 'Prevents Office applications (Word, Excel, PowerPoint) from spawning child processes.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules',
      category: 'Defender ASR',
      docs_url: 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference#block-office-applications-from-creating-child-processes',
      value_map: JSON.stringify({ '0': 'Disabled', '1': 'Block', '2': 'Audit', '6': 'Warn' } as ValueMap),
    },
    {
      normalized_key: 'policy_config_defender_attacksurfacereductionrules_blockofficeapplicationsfromcreatingexecutablecontent',
      name: 'ASR: Block Office applications from creating executable content',
      description: 'Prevents Office applications from writing executable content to disk.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules',
      category: 'Defender ASR',
      docs_url: 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference#block-office-applications-from-creating-executable-content',
      value_map: JSON.stringify({ '0': 'Disabled', '1': 'Block', '2': 'Audit', '6': 'Warn' } as ValueMap),
    },
    {
      normalized_key: 'policy_config_defender_attacksurfacereductionrules_blockofficeapplicationsfrominjecting',
      name: 'ASR: Block Office applications from injecting code into other processes',
      description: 'Prevents Office applications from injecting code into other processes.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules',
      category: 'Defender ASR',
      docs_url: 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference#block-office-applications-from-injecting-code-into-other-processes',
      value_map: JSON.stringify({ '0': 'Disabled', '1': 'Block', '2': 'Audit', '6': 'Warn' } as ValueMap),
    },
    {
      normalized_key: 'policy_config_defender_attacksurfacereductionrules_blockcredentialstealingfromlsass',
      name: 'ASR: Block credential stealing from the Windows local security authority subsystem (lsass.exe)',
      description: 'Prevents credential theft tools from extracting passwords from LSASS memory.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules',
      category: 'Defender ASR',
      docs_url: 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference#block-credential-stealing-from-the-windows-local-security-authority-subsystem',
      value_map: JSON.stringify({ '0': 'Disabled', '1': 'Block', '2': 'Audit', '6': 'Warn' } as ValueMap),
    },
    {
      normalized_key: 'policy_config_defender_attacksurfacereductionrules_blockprocesscreationspawnedfrompsexecandwmicommands',
      name: 'ASR: Block process creations originating from PSExec and WMI commands',
      description: 'Blocks process creation via PsExec and WMI, commonly abused for lateral movement.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules',
      category: 'Defender ASR',
      docs_url: 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference#block-process-creations-originating-from-psexec-and-wmi-commands',
      value_map: JSON.stringify({ '0': 'Disabled', '1': 'Block', '2': 'Audit', '6': 'Warn' } as ValueMap),
    },
    {
      normalized_key: 'policy_config_defender_attacksurfacereductionrules_blockuntrustedunsignedprocessesthatrunfromusb',
      name: 'ASR: Block untrusted and unsigned processes that run from USB',
      description: 'Prevents unsigned executables from running from removable USB media.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules',
      category: 'Defender ASR',
      docs_url: 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference#block-untrusted-and-unsigned-processes-that-run-from-usb',
      value_map: JSON.stringify({ '0': 'Disabled', '1': 'Block', '2': 'Audit', '6': 'Warn' } as ValueMap),
    },
    {
      normalized_key: 'policy_config_defender_attacksurfacereductionrules_blockadobereaderfrommakingchildprocesses',
      name: 'ASR: Block Adobe Reader from creating child processes',
      description: 'Prevents Adobe Reader from spawning child processes, reducing the attack surface from malicious PDFs.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules',
      category: 'Defender ASR',
      docs_url: 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference#block-adobe-reader-from-creating-child-processes',
      value_map: JSON.stringify({ '0': 'Disabled', '1': 'Block', '2': 'Audit', '6': 'Warn' } as ValueMap),
    },
    {
      normalized_key: 'policy_config_defender_attacksurfacereductionrules_blockjavascriptorvbscriptfromlaunchingexecutablecontent',
      name: 'ASR: Block JavaScript or VBScript from launching downloaded executable content',
      description: 'Prevents JS/VBScript from executing downloaded content, blocking a common dropper technique.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules',
      category: 'Defender ASR',
      docs_url: 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference#block-javascript-or-vbscript-from-launching-downloaded-executable-content',
      value_map: JSON.stringify({ '0': 'Disabled', '1': 'Block', '2': 'Audit', '6': 'Warn' } as ValueMap),
    },
    {
      normalized_key: 'policy_config_defender_attacksurfacereductionrules_blockexecutablefilesrunningfromemail',
      name: 'ASR: Block executable files from running unless they meet a prevalence, age, or trusted list criterion',
      description: 'Prevents executables from running if they are not widely trusted, recently seen, or on a whitelist.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules',
      category: 'Defender ASR',
      docs_url: 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference#block-executable-files-from-running-unless-they-meet-a-prevalence-age-or-trusted-list-criterion',
      value_map: JSON.stringify({ '0': 'Disabled', '1': 'Block', '2': 'Audit', '6': 'Warn' } as ValueMap),
    },
    {
      normalized_key: 'policy_config_defender_attacksurfacereductionrules_blockpersistencethroughwmieventsub',
      name: 'ASR: Block persistence through WMI event subscription',
      description: 'Prevents malware from using WMI to maintain persistence across reboots.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules',
      category: 'Defender ASR',
      docs_url: 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference#block-persistence-through-wmi-event-subscription',
      value_map: JSON.stringify({ '0': 'Disabled', '1': 'Block', '2': 'Audit', '6': 'Warn' } as ValueMap),
    },
    {
      normalized_key: 'policy_config_defender_attacksurfacereductionrules_blockabuseofexploitedvulnerablesigneddrivers',
      name: 'ASR: Block abuse of exploited vulnerable signed drivers',
      description: 'Prevents applications from writing a vulnerable signed driver to disk.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules',
      category: 'Defender ASR',
      docs_url: 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference#block-abuse-of-exploited-vulnerable-signed-drivers',
      value_map: JSON.stringify({ '0': 'Disabled', '1': 'Block', '2': 'Audit', '6': 'Warn' } as ValueMap),
    },

    // ─── BitLocker ────────────────────────────────────────────────────────────
    {
      normalized_key: 'policy_config_bitlocker_requiredeviceencryption',
      name: 'BitLocker: Require device encryption',
      description: 'Requires BitLocker drive encryption to be enabled on the device.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/BitLocker/RequireDeviceEncryption',
      category: 'BitLocker',
      docs_url: 'https://learn.microsoft.com/en-us/windows/client-management/mdm/bitlocker-csp#requiredeviceencryption',
      value_map: JSON.stringify({ '0': 'Not Required', '1': 'Required' } as ValueMap),
    },
    {
      normalized_key: 'policy_config_bitlocker_allowwarningforotherdiskencryption',
      name: 'BitLocker: Allow warning for other disk encryption',
      description: 'Controls whether a warning prompt is shown when third-party disk encryption is detected.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/BitLocker/AllowWarningForOtherDiskEncryption',
      category: 'BitLocker',
      docs_url: 'https://learn.microsoft.com/en-us/windows/client-management/mdm/bitlocker-csp#allowwarningforotherdiskencryption',
      value_map: JSON.stringify({ '0': 'Warning Disabled', '1': 'Warning Enabled' } as ValueMap),
    },
    {
      normalized_key: 'policy_config_bitlocker_allowstandarduserencryption',
      name: 'BitLocker: Allow standard user encryption',
      description: 'Allows standard (non-admin) users to enable BitLocker encryption.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/BitLocker/AllowStandardUserEncryption',
      category: 'BitLocker',
      docs_url: 'https://learn.microsoft.com/en-us/windows/client-management/mdm/bitlocker-csp#allowstandarduserencryption',
      value_map: JSON.stringify({ '0': 'Not Allowed', '1': 'Allowed' } as ValueMap),
    },
    {
      normalized_key: 'policy_config_bitlocker_encryptionmethodbydrivetype',
      name: 'BitLocker: Encryption method by drive type',
      description: 'Specifies the BitLocker encryption algorithm and cipher strength for OS, fixed, and removable drives.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/BitLocker/EncryptionMethodByDriveType',
      category: 'BitLocker',
      docs_url: 'https://learn.microsoft.com/en-us/windows/client-management/mdm/bitlocker-csp#encryptionmethodbydrivetype',
      value_map: JSON.stringify({ '3': 'AES-CBC 128-bit', '4': 'AES-CBC 256-bit', '6': 'XTS-AES 128-bit', '7': 'XTS-AES 256-bit' } as ValueMap),
    },
    {
      normalized_key: 'policy_config_bitlocker_systemdrivesrequirestartupauthentication',
      name: 'BitLocker: Require startup authentication (OS drive)',
      description: 'Requires additional authentication at startup for the operating system drive.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/BitLocker/SystemDrivesRequireStartupAuthentication',
      category: 'BitLocker',
      docs_url: 'https://learn.microsoft.com/en-us/windows/client-management/mdm/bitlocker-csp#systemdrivesrequirestartupauthentication',
      value_map: JSON.stringify({ '0': 'Disabled', '1': 'Enabled' } as ValueMap),
    },
    {
      normalized_key: 'policy_config_bitlocker_systemdrivesminimumpinenforcement',
      name: 'BitLocker: Configure minimum PIN length for startup',
      description: 'Sets the minimum number of digits required for the BitLocker startup PIN.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/BitLocker/SystemDrivesMinimumPINLength',
      category: 'BitLocker',
      docs_url: 'https://learn.microsoft.com/en-us/windows/client-management/mdm/bitlocker-csp#systemdrivesminimumpinlength',
      value_map: JSON.stringify({} as ValueMap),
    },
    {
      normalized_key: 'policy_config_bitlocker_fixeddrivesrequireencryption',
      name: 'BitLocker: Fixed data drives require encryption',
      description: 'Requires BitLocker encryption on fixed data drives.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/BitLocker/FixedDrivesRequireEncryption',
      category: 'BitLocker',
      docs_url: 'https://learn.microsoft.com/en-us/windows/client-management/mdm/bitlocker-csp#fixeddrivesrequireencryption',
      value_map: JSON.stringify({ '0': 'Not Required', '1': 'Required' } as ValueMap),
    },
    {
      normalized_key: 'policy_config_bitlocker_removabledrivesrequireencryption',
      name: 'BitLocker: Removable drives require encryption',
      description: 'Requires BitLocker encryption on removable data drives.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/BitLocker/RemovableDrivesRequireEncryption',
      category: 'BitLocker',
      docs_url: 'https://learn.microsoft.com/en-us/windows/client-management/mdm/bitlocker-csp#removabledrivesrequireencryption',
      value_map: JSON.stringify({ '0': 'Not Required', '1': 'Required' } as ValueMap),
    },

    // ─── LAPS ─────────────────────────────────────────────────────────────────
    {
      normalized_key: 'laps_policies_backupdirectory',
      name: 'LAPS: Backup directory',
      description: 'Specifies where the local admin password is backed up (Disabled, Azure AD, or Active Directory).',
      csp_path: './Device/Vendor/MSFT/LAPS/Policies/BackupDirectory',
      category: 'LAPS',
      docs_url: 'https://learn.microsoft.com/en-us/windows/client-management/mdm/laps-csp#policiesbackupdirectory',
      value_map: JSON.stringify({ '0': 'Disabled (Not backed up)', '1': 'Azure Active Directory', '2': 'Active Directory' } as ValueMap),
    },
    {
      normalized_key: 'laps_policies_passwordlength',
      name: 'LAPS: Password length',
      description: 'Specifies the length of the managed local administrator account password.',
      csp_path: './Device/Vendor/MSFT/LAPS/Policies/PasswordLength',
      category: 'LAPS',
      docs_url: 'https://learn.microsoft.com/en-us/windows/client-management/mdm/laps-csp#policiespasswordlength',
      value_map: JSON.stringify({} as ValueMap),
    },
    {
      normalized_key: 'laps_policies_passwordcomplexity',
      name: 'LAPS: Password complexity',
      description: 'Specifies the complexity requirements for the managed local administrator account password.',
      csp_path: './Device/Vendor/MSFT/LAPS/Policies/PasswordComplexity',
      category: 'LAPS',
      docs_url: 'https://learn.microsoft.com/en-us/windows/client-management/mdm/laps-csp#policiespasswordcomplexity',
      value_map: JSON.stringify({ '1': 'Large letters', '2': 'Large + small letters', '3': 'Large + small letters + numbers', '4': 'Large + small letters + numbers + special characters', '5': 'Large + small letters + numbers + special characters (enhanced)' } as ValueMap),
    },
    {
      normalized_key: 'laps_policies_passwordagedays',
      name: 'LAPS: Password age in days',
      description: 'Specifies the maximum age of the managed local administrator account password in days.',
      csp_path: './Device/Vendor/MSFT/LAPS/Policies/PasswordAgeDays',
      category: 'LAPS',
      docs_url: 'https://learn.microsoft.com/en-us/windows/client-management/mdm/laps-csp#policiespasswordagedays',
      value_map: JSON.stringify({} as ValueMap),
    },
    {
      normalized_key: 'laps_policies_administratoraccountname',
      name: 'LAPS: Administrator account name',
      description: 'Specifies the custom administrator account name to manage. Leave blank to manage the built-in account.',
      csp_path: './Device/Vendor/MSFT/LAPS/Policies/AdministratorAccountName',
      category: 'LAPS',
      docs_url: 'https://learn.microsoft.com/en-us/windows/client-management/mdm/laps-csp#policiesadministratoraccountname',
      value_map: JSON.stringify({} as ValueMap),
    },
    {
      normalized_key: 'laps_policies_postauthenticationactions',
      name: 'LAPS: Post-authentication actions',
      description: 'Specifies actions to take after a successful authentication using the managed account.',
      csp_path: './Device/Vendor/MSFT/LAPS/Policies/PostAuthenticationActions',
      category: 'LAPS',
      docs_url: 'https://learn.microsoft.com/en-us/windows/client-management/mdm/laps-csp#policiespostauthenticationactions',
      value_map: JSON.stringify({ '1': 'Reset password', '3': 'Reset password and logoff', '5': 'Reset password and reboot' } as ValueMap),
    },

    // ─── Defender (General) ───────────────────────────────────────────────────
    {
      normalized_key: 'policy_config_defender_allowrealtimemonitoring',
      name: 'Defender: Allow real-time monitoring',
      description: 'Enables or disables Microsoft Defender Antivirus real-time protection.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/Defender/AllowRealTimeMonitoring',
      category: 'Defender',
      docs_url: 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#allowrealtimemonitoring',
      value_map: JSON.stringify({ '0': 'Not Allowed', '1': 'Allowed' } as ValueMap),
    },
    {
      normalized_key: 'policy_config_defender_allowcloudprotection',
      name: 'Defender: Allow cloud protection',
      description: 'Allows Microsoft Defender to join the Microsoft Active Protection Service for cloud-delivered protection.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/Defender/AllowCloudProtection',
      category: 'Defender',
      docs_url: 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#allowcloudprotection',
      value_map: JSON.stringify({ '0': 'Not Allowed', '1': 'Allowed' } as ValueMap),
    },
    {
      normalized_key: 'policy_config_defender_cloudblocklevel',
      name: 'Defender: Cloud block level',
      description: 'Specifies the level of aggressiveness for blocking suspicious files using cloud protection.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/Defender/CloudBlockLevel',
      category: 'Defender',
      docs_url: 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#cloudblocklevel',
      value_map: JSON.stringify({ '0': 'Not configured', '2': 'High', '4': 'High+', '6': 'Zero tolerance' } as ValueMap),
    },
    {
      normalized_key: 'policy_config_defender_allowioavprotection',
      name: 'Defender: Allow IOAV protection',
      description: 'Enables scanning of all downloaded files and attachments.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/Defender/AllowIOAVProtection',
      category: 'Defender',
      docs_url: 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#allowioavprotection',
      value_map: JSON.stringify({ '0': 'Not Allowed', '1': 'Allowed' } as ValueMap),
    },
    {
      normalized_key: 'policy_config_defender_puaprotection',
      name: 'Defender: PUA protection',
      description: 'Configures detection for potentially unwanted applications (PUAs/PUPs).',
      csp_path: './Device/Vendor/MSFT/Policy/Config/Defender/PUAProtection',
      category: 'Defender',
      docs_url: 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#puaprotection',
      value_map: JSON.stringify({ '0': 'Disabled', '1': 'Enabled', '2': 'Audit' } as ValueMap),
    },
    {
      normalized_key: 'policy_config_defender_allowscriptscanning',
      name: 'Defender: Allow script scanning',
      description: 'Enables scanning of scripts in Internet Explorer and Windows Script Host.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/Defender/AllowScriptScanning',
      category: 'Defender',
      docs_url: 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#allowscriptscanning',
      value_map: JSON.stringify({ '0': 'Not Allowed', '1': 'Allowed' } as ValueMap),
    },
    {
      normalized_key: 'policy_config_defender_submitsamplesconsent',
      name: 'Defender: Submit samples consent',
      description: 'Controls whether Defender automatically submits suspicious samples to Microsoft.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/Defender/SubmitSamplesConsent',
      category: 'Defender',
      docs_url: 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#submitsamplesconsent',
      value_map: JSON.stringify({ '0': 'Always prompt', '1': 'Send safe samples automatically', '2': 'Never send', '3': 'Send all samples automatically' } as ValueMap),
    },

    // ─── Windows Firewall ─────────────────────────────────────────────────────
    {
      normalized_key: 'policy_config_firewall_enabledomainnetworkfirewall',
      name: 'Firewall: Enable domain network firewall',
      description: 'Enables the Windows Firewall for domain network profiles.',
      csp_path: './Vendor/MSFT/Firewall/MdmStore/DomainProfile/EnableFirewall',
      category: 'Windows Firewall',
      docs_url: 'https://learn.microsoft.com/en-us/windows/client-management/mdm/firewall-csp#mdmstoreglobalprofileenablefirewall',
      value_map: JSON.stringify({ 'false': 'Disabled', 'true': 'Enabled' } as ValueMap),
    },
    {
      normalized_key: 'policy_config_firewall_enableprivatenetworkfirewall',
      name: 'Firewall: Enable private network firewall',
      description: 'Enables the Windows Firewall for private network profiles.',
      csp_path: './Vendor/MSFT/Firewall/MdmStore/PrivateProfile/EnableFirewall',
      category: 'Windows Firewall',
      docs_url: 'https://learn.microsoft.com/en-us/windows/client-management/mdm/firewall-csp',
      value_map: JSON.stringify({ 'false': 'Disabled', 'true': 'Enabled' } as ValueMap),
    },

    // ─── Windows Update ───────────────────────────────────────────────────────
    {
      normalized_key: 'policy_config_update_allowautoupdate',
      name: 'Update: Allow auto update',
      description: 'Controls whether automatic Windows Updates are allowed and how they behave.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/Update/AllowAutoUpdate',
      category: 'Windows Update',
      docs_url: 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update#allowautoupdate',
      value_map: JSON.stringify({ '0': 'Notify download', '1': 'Auto install at maintenance time', '2': 'Auto install and restart at maintenance time', '3': 'Auto install and restart at scheduled time', '4': 'Auto install and restart without end-user control', '5': 'Turn off automatic updates' } as ValueMap),
    },
    {
      normalized_key: 'policy_config_update_managepreviewbuilds',
      name: 'Update: Manage preview builds',
      description: 'Controls whether users can install Windows Insider preview builds.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/Update/ManagePreviewBuilds',
      category: 'Windows Update',
      docs_url: 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update#managepreviewbuilds',
      value_map: JSON.stringify({ '0': 'Disabled', '1': 'Enabled', '2': 'Preview builds not enabled' } as ValueMap),
    },

    // ─── SmartScreen ─────────────────────────────────────────────────────────
    {
      normalized_key: 'policy_config_smartscreen_enablesmartscreeninshell',
      name: 'SmartScreen: Enable SmartScreen in Shell',
      description: 'Enables Windows Defender SmartScreen for apps and files downloaded from the internet.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/SmartScreen/EnableSmartScreenInShell',
      category: 'SmartScreen',
      docs_url: 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-smartscreen#enablesmartscreeninshell',
      value_map: JSON.stringify({ '0': 'Disabled', '1': 'Enabled' } as ValueMap),
    },
    {
      normalized_key: 'policy_config_smartscreen_preventoverrideforfilesinshell',
      name: 'SmartScreen: Prevent override for files in Shell',
      description: 'Prevents users from overriding SmartScreen warnings about unverified files.',
      csp_path: './Device/Vendor/MSFT/Policy/Config/SmartScreen/PreventOverrideForFilesInShell',
      category: 'SmartScreen',
      docs_url: 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-smartscreen#preventoverrideforfilesinshell',
      value_map: JSON.stringify({ '0': 'Disabled (user can override)', '1': 'Enabled (user cannot override)' } as ValueMap),
    },
  ];

  const insertMany = database.transaction((records: Array<Omit<PolicyRecord, 'id'>>) => {
    for (const record of records) {
      upsertPolicy(record);
    }
  });

  // Insert pre-built KB first, then hand-curated data on top.
  // upsertPolicy uses INSERT … ON CONFLICT DO UPDATE, so the second insertMany
  // overwrites any overlapping keys with the more precise hand-curated values.
  insertMany(kbData);
  insertMany(seedData);
}
