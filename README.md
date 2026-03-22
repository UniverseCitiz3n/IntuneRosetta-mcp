# IntuneRosetta-mcp

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that **translates raw OMA-URI / CSP path strings into structured, human-readable Intune policy metadata** — search 800+ pre-built policy records and resolve human-readable names to CSP keys, all from your AI assistant.

## Quick start

No local installation required. Use `npx` to run the server on-demand:

```bash
npx github:UniverseCitiz3n/IntuneRosetta-mcp
```

> **Prerequisites:** Node.js ≥ 18 and `git` available on your PATH environment variable.

---

## Install in your MCP client

### VS Code (GitHub Copilot)

Install with one click:

| Platform | VS Code | VS Code Insiders |
|---|---|---|
| **macOS / Linux** | [![Install in VS Code](https://img.shields.io/badge/VS_Code-Install_Server-0098FF?style=flat-square&logo=visualstudiocode&logoColor=ffffff)](https://vscode.dev/redirect?url=vscode:mcp/install?%7B%22name%22%3A%22intunerosetta%22%2C%22type%22%3A%22stdio%22%2C%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22-y%22%2C%22github%3AUniverseCitiz3n%2FIntuneRosetta-mcp%22%5D%7D) | [![Install in VS Code Insiders](https://img.shields.io/badge/VS_Code_Insiders-Install_Server-24bfa5?style=flat-square&logo=visualstudiocode&logoColor=ffffff)](https://vscode.dev/redirect?url=vscode-insiders:mcp/install?%7B%22name%22%3A%22intunerosetta%22%2C%22type%22%3A%22stdio%22%2C%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22-y%22%2C%22github%3AUniverseCitiz3n%2FIntuneRosetta-mcp%22%5D%7D) |
| **Windows** | [![Install in VS Code](https://img.shields.io/badge/VS_Code-Install_Server-0098FF?style=flat-square&logo=visualstudiocode&logoColor=ffffff)](https://vscode.dev/redirect?url=vscode:mcp/install?%7B%22name%22%3A%22intunerosetta%22%2C%22type%22%3A%22stdio%22%2C%22command%22%3A%22cmd%22%2C%22args%22%3A%5B%22%2Fc%22%2C%22npx%22%2C%22-y%22%2C%22github%3AUniverseCitiz3n%2FIntuneRosetta-mcp%22%5D%7D) | [![Install in VS Code Insiders](https://img.shields.io/badge/VS_Code_Insiders-Install_Server-24bfa5?style=flat-square&logo=visualstudiocode&logoColor=ffffff)](https://vscode.dev/redirect?url=vscode-insiders:mcp/install?%7B%22name%22%3A%22intunerosetta%22%2C%22type%22%3A%22stdio%22%2C%22command%22%3A%22cmd%22%2C%22args%22%3A%5B%22%2Fc%22%2C%22npx%22%2C%22-y%22%2C%22github%3AUniverseCitiz3n%2FIntuneRosetta-mcp%22%5D%7D) |

Or add manually to `.vscode/mcp.json` in your workspace (create the file if it doesn't exist):

```json
{
  "servers": {
    "intunerosetta": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "github:UniverseCitiz3n/IntuneRosetta-mcp"]
    }
  }
}
```

### Claude Desktop

Edit your Claude Desktop config file:

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "intunerosetta": {
      "command": "npx",
      "args": ["-y", "github:UniverseCitiz3n/IntuneRosetta-mcp"]
    }
  }
}
```

### Claude Code

Add to your project's `mcp.json` file:

```json
{
  "mcpServers": {
    "intunerosetta": {
      "command": "npx",
      "args": ["-y", "github:UniverseCitiz3n/IntuneRosetta-mcp"]
    }
  }
}
```

### GitHub Copilot Coding Agent (repository settings)

In your repository's **Settings → Copilot → MCP servers**, add:

```json
{
  "mcpServers": {
    "intunerosetta": {
      "type": "local",
      "command": "npx",
      "args": ["-y", "github:UniverseCitiz3n/IntuneRosetta-mcp"],
      "tools": ["*"]
    }
  }
}
```

---

## Available tools

| Tool | Input | Description |
|---|---|---|
| `translate_csp_key` | `key` (string) | Translates a raw underscore-delimited OMA-URI / CSP path string into structured, human-readable policy metadata |
| `batch_translate` | `keys` (string[]) | Translates an array of CSP path strings in one call |
| `search_policy` | `query` (string), `limit` (number, optional) | Fuzzy keyword search across the policy database by name, description, category, or CSP path fragment |
| `resolve_to_csp` | `query` (string), `limit` (number, optional) | Resolves a human-readable policy name or keyword to matching CSP key(s) and full metadata |
| `refresh_kb` | `force` (boolean, optional) | Rebuilds the local KB by querying msgraph-kb with all predefined search terms. Requires `MSGRAPH_KB_COMMAND` to be set |

---

## Example usage

### Translate a raw CSP key

```
translate_csp_key("device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts_2")
```

Returns:

```json
{
  "name": "Block execution of potentially obfuscated scripts",
  "description": "This rule detects suspicious properties within an obfuscated script.",
  "value": "2",
  "csp_path": "./Device/Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules",
  "category": "Defender ASR",
  "docs_url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction"
}
```

### Search for a policy by keyword

```
search_policy("bitlocker startup authentication")
```

### Resolve a human-readable name to CSP key

```
resolve_to_csp("block obfuscated scripts")
```

---

## msgraph-kb integration (optional)

IntuneRosetta can connect to the [msgraph-kb MCP server](https://github.com/UniverseCitiz3n/msgraph-kb-mcp) to enrich its local knowledge base with live Microsoft Graph API metadata.

Set the following environment variables to enable this integration:

| Variable | Description | Example |
|---|---|---|
| `MSGRAPH_KB_COMMAND` | Executable used to launch the msgraph-kb server | `node` or `npx` |
| `MSGRAPH_KB_ARGS` | Space-separated arguments passed to the command | `/path/to/msgraph-kb/dist/index.js` |

When `MSGRAPH_KB_COMMAND` is set, IntuneRosetta automatically queries msgraph-kb in the background at startup and populates any missing records in the local database. You can also trigger a manual refresh at any time with the `refresh_kb` tool.

**Example — VS Code with msgraph-kb integration:**

```json
{
  "servers": {
    "intunerosetta": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "github:UniverseCitiz3n/IntuneRosetta-mcp"],
      "env": {
        "MSGRAPH_KB_COMMAND": "npx",
        "MSGRAPH_KB_ARGS": "-y github:UniverseCitiz3n/msgraph-kb-mcp"
      }
    }
  }
}
```

---

## Local development

Clone the repo, install dependencies, and build:

```bash
git clone https://github.com/UniverseCitiz3n/IntuneRosetta-mcp.git
cd IntuneRosetta-mcp
npm install
npm run build
node dist/index.js
```

Point any MCP client at the built binary:

```json
{
  "mcpServers": {
    "intunerosetta": {
      "command": "node",
      "args": ["/absolute/path/to/IntuneRosetta-mcp/dist/index.js"]
    }
  }
}
```

Run tests:

```bash
npm test
```

---

## How it works

At startup the server seeds an in-memory **SQLite database** from a pre-built knowledge base (`db/intune-policies.json`, 800+ records covering Windows, Linux, and Apple ADE) and applies a set of hand-curated seed records on top. Records include:

- `normalized_key` — underscore-delimited CSP path (lowercase, `device_vendor_msft_` prefix stripped)
- `name` / `description` — human-readable label and explanation
- `csp_path` — canonical OMA-URI path (e.g. `./Device/Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules`)
- `category` — policy area (e.g. `Defender ASR`, `BitLocker`, `LAPS`)
- `docs_url` — link to Microsoft documentation
- `value_map` — map of raw integer values to human-readable labels (e.g. `{"0":"Disabled","1":"Block","2":"Audit"}`)

When a `translate_csp_key` or `search_policy` call arrives, the server looks up the normalized key in SQLite, attaches the decoded value label, and returns structured `PolicyMetadata`.

If `MSGRAPH_KB_COMMAND` is configured, a background KB build queries the [msgraph-kb MCP server](https://github.com/UniverseCitiz3n/msgraph-kb-mcp) with 20 predefined Intune-related search terms and upserts any new results into the local database — no manual curation required for Graph API endpoints.

---

## License

ISC