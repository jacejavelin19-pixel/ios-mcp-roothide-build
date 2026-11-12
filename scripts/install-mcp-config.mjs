#!/usr/bin/env node
/**
 * One-command host MCP configuration installer for ios-mcp.
 * Supports Claude Desktop, Claude Code, Codex, OpenCode, VS Code, and Antigravity.
 *
 * Usage:
 *   node scripts/install-mcp-config.mjs --url http://127.0.0.1:18080/mcp --client all
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

function parseArgs(argv) {
  const opts = {
    url: process.env.IOS_MCP_URL || "http://127.0.0.1:18080/mcp",
    client: "all",
    name: "ios-mcp",
    dryRun: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--url" && argv[i + 1]) opts.url = argv[++i];
    else if (a === "--host" && argv[i + 1]) {
      const host = argv[++i];
      const port = opts.port || "8090";
      opts.url = `http://${host}:${port}/mcp`;
    } else if (a === "--port" && argv[i + 1]) {
      opts.port = argv[++i];
    } else if (a === "--client" && argv[i + 1]) opts.client = argv[++i].toLowerCase();
    else if (a === "--name" && argv[i + 1]) opts.name = argv[++i];
    else if (a === "--dry-run") opts.dryRun = true;
  }
  return opts;
}

function getClientPaths() {
  const home = os.homedir();
  const isWin = process.platform === "win32";
  const isMac = process.platform === "darwin";
  const appData = process.env.APPDATA || path.join(home, "AppData", "Roaming");

  return {
    claude: isWin
      ? path.join(appData, "Claude", "claude_desktop_config.json")
      : isMac
      ? path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
      : path.join(home, ".config", "Claude", "claude_desktop_config.json"),
    "claude-code": path.join(home, ".claude.json"),
    codex: path.join(home, ".codex", "mcp.json"),
    opencode: path.join(home, ".config", "opencode", "opencode.json"),
    vscode: isWin
      ? path.join(appData, "Code", "User", "mcp.json")
      : isMac
      ? path.join(home, "Library", "Application Support", "Code", "User", "mcp.json")
      : path.join(home, ".config", "Code", "User", "mcp.json"),
    antigravity: path.join(home, ".gemini", "antigravity", "mcp_config.json"),
  };
}

function updateJsonConfig(filePath, serverName, url, rootKey = "mcpServers", dryRun = false) {
  let obj = {};
  if (fs.existsSync(filePath)) {
    try {
      obj = JSON.parse(fs.readFileSync(filePath, "utf8"));
    } catch {
      obj = {};
    }
  }
  if (!obj[rootKey] || typeof obj[rootKey] !== "object") {
    obj[rootKey] = {};
  }
  obj[rootKey][serverName] = {
    type: "streamable-http",
    url,
  };
  if (!dryRun) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, JSON.stringify(obj, null, 2) + "\n", "utf8");
  }
  return { clientFile: filePath, updated: !dryRun, entry: obj[rootKey][serverName] };
}

function main() {
  const opts = parseArgs(process.argv);
  const paths = getClientPaths();
  const targets =
    opts.client === "all"
      ? Object.keys(paths)
      : opts.client.split(",").map((s) => s.trim()).filter((k) => paths[k]);

  const results = [];
  for (const target of targets) {
    const filePath = paths[target];
    if (target === "all") continue;
    const rootKey = target === "vscode" ? "servers" : "mcpServers";
    if (opts.client === "all" && !fs.existsSync(path.dirname(filePath)) && target !== "claude-code") {
      continue;
    }
    results.push({
      client: target,
      ...updateJsonConfig(filePath, opts.name, opts.url, rootKey, opts.dryRun),
    });
  }
  console.log(JSON.stringify({ ok: true, url: opts.url, results }, null, 2));
}

main();
