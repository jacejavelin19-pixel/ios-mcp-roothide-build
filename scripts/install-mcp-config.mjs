#!/usr/bin/env node
/**
 * One-command host MCP configuration installer for ios-mcp.
 * Supports Claude Desktop, Claude Code, Codex (.codex/config.toml & mcp.json),
 * OpenCode, VS Code, and Antigravity (.gemini/config/mcp_config.json).
 *
 * Usage:
 *   node scripts/install-mcp-config.mjs --url http://127.0.0.1:8090/mcp --client all
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

function parseArgs(argv) {
  const opts = {
    url: process.env.IOS_MCP_URL || "http://127.0.0.1:8090/mcp",
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
    codex: path.join(home, ".codex", "config.toml"),
    opencode: path.join(home, ".config", "opencode", "opencode.json"),
    vscode: isWin
      ? path.join(appData, "Code", "User", "mcp.json")
      : isMac
      ? path.join(home, "Library", "Application Support", "Code", "User", "mcp.json")
      : path.join(home, ".config", "Code", "User", "mcp.json"),
    antigravity: path.join(home, ".gemini", "config", "mcp_config.json"),
  };
}

function updateTomlConfig(filePath, serverName, url, dryRun = false) {
  let content = fs.existsSync(filePath) ? fs.readFileSync(filePath, "utf8") : "";
  const sectionRegex = new RegExp(`(\\[mcp_servers\\.${serverName}\\][\\s\\S]*?url\\s*=\\s*)"[^"]*"`, "m");
  if (sectionRegex.test(content)) {
    content = content.replace(sectionRegex, `$1"${url}"`);
  } else {
    content += `\n[mcp_servers.${serverName}]\nurl = "${url}"\n`;
  }
  if (!dryRun) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, content, "utf8");
  }
  return { clientFile: filePath, updated: !dryRun, entry: { url } };
}

function updateJsonConfig(filePath, target, serverName, url, dryRun = false) {
  let obj = {};
  if (fs.existsSync(filePath)) {
    try {
      obj = JSON.parse(fs.readFileSync(filePath, "utf8"));
    } catch {
      obj = {};
    }
  }
  let entry;
  if (target === "opencode") {
    if (!obj.mcp || typeof obj.mcp !== "object") obj.mcp = {};
    if (obj.mcp.servers && typeof obj.mcp.servers === "object") {
      obj.mcp.servers[serverName] = { type: "remote", url, oauth: false };
      entry = obj.mcp.servers[serverName];
    } else {
      obj.mcp[serverName] = { type: "remote", url, oauth: false };
      entry = obj.mcp[serverName];
    }
  } else if (target === "claude" && process.platform === "win32") {
    if (!obj.mcpServers || typeof obj.mcpServers !== "object") obj.mcpServers = {};
    obj.mcpServers[serverName] = {
      command: "C:\\Program Files\\nodejs\\node.exe",
      args: [
        "C:\\Program Files\\nodejs\\node_modules\\npm\\bin\\npx-cli.js",
        "-y",
        "mcp-remote",
        url,
        "--allow-http",
      ],
    };
    entry = obj.mcpServers[serverName];
  } else {
    const rootKey = target === "vscode" ? "servers" : "mcpServers";
    if (!obj[rootKey] || typeof obj[rootKey] !== "object") obj[rootKey] = {};
    obj[rootKey][serverName] = target === "antigravity" ? { url } : { type: "streamable-http", url };
    entry = obj[rootKey][serverName];
  }
  if (!dryRun) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, JSON.stringify(obj, null, 2) + "\n", "utf8");
  }
  return { clientFile: filePath, updated: !dryRun, entry };
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
    if (opts.client === "all" && !fs.existsSync(path.dirname(filePath)) && target !== "claude-code") {
      continue;
    }
    const res =
      target === "codex"
        ? updateTomlConfig(filePath, opts.name, opts.url, opts.dryRun)
        : updateJsonConfig(filePath, target, opts.name, opts.url, opts.dryRun);
    results.push({ client: target, ...res });
  }
  console.log(JSON.stringify({ ok: true, url: opts.url, results }, null, 2));
}

main();
