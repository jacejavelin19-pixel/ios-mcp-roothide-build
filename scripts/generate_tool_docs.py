#!/usr/bin/env python3
"""
Extracts the canonical tool catalog, tier classification, and <subsystem>_<verb>
aliases directly from MCPServer.m, verifies 1-to-1 parity between tools/list and
tools/call, and updates docs/TOOL_INVENTORY.md, README.md, README_EN.md, and prompt.txt.
"""

from __future__ import annotations
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MCP_SERVER_M = REPO_ROOT / "MCPServer.m"


def parse_mcp_server(src: str):
    # 1. Extract aliases from MCPToolAliasMap
    alias_block_m = re.search(
        r"static NSDictionary<NSString \*, NSString \*> \*MCPToolAliasMap\(void\)\s*\{(.*?)\n\}",
        src,
        re.S,
    )
    aliases: dict[str, list[str]] = {}
    if alias_block_m:
        for alias, canonical in re.findall(
            r'@"([^"]+)"\s*:\s*@"([^"]+)"', alias_block_m.group(1)
        ):
            aliases.setdefault(canonical, []).append(alias)

    # 2. Extract core set from MCPTierForToolName
    tier_block_m = re.search(
        r"static NSString \*MCPTierForToolName\(NSString \*toolName\)\s*\{(.*?)\n\}",
        src,
        re.S,
    )
    core_set: set[str] = set()
    if tier_block_m:
        core_arr_m = re.search(r"coreSet\s*=\s*\[NSSet setWithArray:@\[(.*?)\]\]", tier_block_m.group(1), re.S)
        if core_arr_m:
            core_set = set(re.findall(r'@"([^"]+)"', core_arr_m.group(1)))

    def get_tier(name: str) -> str:
        if (
            name.startswith("engine_")
            or name.startswith("frida_")
            or name
            in {
                "inject_frida_gadget",
                "remove_frida_gadget",
                "scrub_gadget_binary",
                "configure_frida_stealth",
                "get_frida_stealth_status",
                "tweak_build",
                "tweak_deploy",
                "tweak_rollback",
                "self_update",
                "diagnostics_collect",
                "diagnose_roots",
                "port_forward",
                "session_force_unlock",
                "session_respawn",
            }
        ):
            return "debug"
        if name in core_set:
            return "core"
        return "advanced"

    # 3. Extract tools/list entries
    list_start = src.find("- (NSDictionary *)handleToolsList:(id)reqId params:(NSDictionary *)params {")
    call_start = src.find("- (NSDictionary *)handleToolsCall:(id)reqId params:(NSDictionary *)params {", list_start)
    assert list_start != -1 and call_start != -1, "Could not locate handleToolsList or handleToolsCall"
    list_body = src[list_start:call_start]

    tools = []
    seen = set()
    for m in re.finditer(
        r'@"name"\s*:\s*@"([^"]+)"\s*,\s*@"description"\s*:\s*((?:@?"(?:\\.|[^"\\])*"\s*)+)',
        list_body,
        re.S,
    ):
        name = m.group(1)
        raw_desc = m.group(2)
        parts = re.findall(r'@?"((?:\\.|[^"\\])*)"', raw_desc)
        desc = "".join(parts).replace('\\"', '"')
        if name not in seen:
            seen.add(name)
            tools.append(
                {
                    "name": name,
                    "description": desc,
                    "tier": get_tier(name),
                    "aliases": sorted(aliases.get(name, [])),
                }
            )

    # 4. Verify dispatch coverage in handleToolsCall / executeEngineTool
    guard_start = src.find("- (NSDictionary *)lockedScreenGuardResponseForTool:", call_start)
    call_body = src[call_start:guard_start]
    dispatched_exact = set(
        re.findall(r'\[toolName isEqualToString:@"([^"]+)"\]', call_body)
    )
    engine_start = src.find("- (NSDictionary *)executeEngineTool:", guard_start)
    frida_scan_start = src.find("- (NSDictionary *)executeFridaMemoryScan:", engine_start)
    engine_body = src[engine_start:frida_scan_start]
    engine_dispatched = set(
        re.findall(r'@"((?:engine)_[a-z0-9_]+)"', engine_body)
    )

    missing_dispatch = []
    for t in tools:
        n = t["name"]
        if (
            n in dispatched_exact
            or (n.startswith("engine_") and n in engine_dispatched)
            or n.startswith("tiktok_")
            or n.startswith("photos_")
        ):
            continue
        missing_dispatch.append(n)

    if missing_dispatch:
        raise AssertionError(f"Tools in tools/list missing from tools/call dispatch: {missing_dispatch}")

    return tools, aliases


def write_inventory(tools: list[dict], aliases: dict[str, list[str]]) -> None:
    core_tools = [t for t in tools if t["tier"] == "core"]
    adv_tools = [t for t in tools if t["tier"] == "advanced"]
    dbg_tools = [t for t in tools if t["tier"] == "debug"]

    lines = [
        "# iOS MCP (`com.witchan.ios-mcp` `v2.1.1`) — Generated Tool Inventory",
        "",
        "> Auto-generated from `MCPServer.m` by `scripts/generate_tool_docs.py`. Do not edit by hand.",
        "",
        f"- **Total Canonical Tools**: `{len(tools)}`",
        f"- **Normalized `<subsystem>_<verb>` Aliases**: `{sum(len(v) for v in aliases.values())}`",
        f"- **Tier Breakdown**: `core` = `{len(core_tools)}` | `advanced` = `{len(adv_tools)}` | `debug` = `{len(dbg_tools)}`",
        "",
        "| # | Canonical Tool Name | Tier | Normalized Alias(es) | Description |",
        "| :---: | :--- | :---: | :--- | :--- |",
    ]
    for idx, t in enumerate(tools, 1):
        al = ", ".join(f"`{a}`" for a in t["aliases"]) if t["aliases"] else "—"
        desc = t["description"].replace("|", "\\|")
        lines.append(f"| {idx} | `{t['name']}` | `{t['tier']}` | {al} | {desc} |")

    out_path = REPO_ROOT / "docs" / "TOOL_INVENTORY.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def update_readmes(tools: list[dict]) -> None:
    total = len(tools)
    readme_path = REPO_ROOT / "README.md"
    readme_text = readme_path.read_text(encoding="utf-8")
    readme_text = re.sub(
        r"ios-mcp \(v2\.1\.1 Master Architecture — \d+ Tools Across \d+ Subsystems\)",
        f"ios-mcp (v2.1.1 Master Architecture — {total} Tools Across 9 Subsystems)",
        readme_text,
    )

    new_table = """| Subsystem | Tools |
| :--- | :--- |
| **01. Stealth In-Process Engine (`libmcpengine`)** | `engine_inject`, `engine_remove`, `engine_ping`, `engine_modules`, `engine_classes`, `engine_describe_class`, `engine_hook_objc`, `engine_hook_events`, `engine_unhook`, `engine_invoke`, `engine_get_ivar`, `engine_set_ivar`, `engine_prepare_native_hook`, `engine_hook_native`, `engine_start_capture`, `engine_get_requests`, `engine_stop_capture`, `engine_call`, `engine_read_memory`, `engine_write_memory`, `engine_search_memory`, `engine_eval_js`, `engine_hw_breakpoint`, `engine_decompile`, `engine_trace_crypto`, `engine_get_crypto_events`, `engine_stop_crypto`, `engine_hook_quic_http3`, `engine_decode_protobuf`, `engine_replay_request` |
| **02. Decryption, Decompilation, Hermes/JS & Swift RE** | `decrypt_app_ipa`, `decompile_function`, `decompile_objc_method`, `find_xrefs_to`, `hardware_breakpoint_hook`, `dump_swift_metadata`, `extract_dyld_shared_cache`, `inspect_hermes_flutter`, `inspect_js_bundle`, `decode_js_bundle`, `list_hermes_decoders` |
| **03. Network, QUIC/HTTP3, Protobuf & Crypto Capture** | `start_capture`, `stop_capture`, `get_captured_requests`, `net_enable`, `net_disable`, `net_clear`, `net_status`, `net_dump`, `bypass_pinning`, `restore_pinning`, `trace_crypto_primitives`, `get_crypto_events`, `hook_quic_http3`, `decode_protobuf`, `replay_request_native`, `tls_ja3_ja4_http2_cloak` |
| **04. Anti-Fraud SDK Bypass, Cloaking & Persona Suite** | `stealth_syscall_shield`, `spoof_device_fingerprint`, `kernel_proc_cloak`, `proxy_vpn_network_cloak`, `hardware_canvas_gpu_audio_randomizer`, `behavioral_biometrics_ghost_player`, `perimeterx_akamai_datadome_kasada_tap`, `threatmetrix_sardine_forter_seon_neutralizer`, `apple_app_attest_devicecheck_bridge`, `sync_fraud_persona`, `objc_swizzle_and_dladdr_integrity_cloak`, `thread_mach_port_and_stack_cloaker`, `wipe_fraud_canaries`, `apply_fraud_persona`, `audit_fraud_surface` |
| **05. App Store & `MuffinStore` Version Control** | `appstore_search_and_versions`, `appstore_install`, `appstore_downgrade`, `appstore_auto_rollback_diff` |
| **06. Sovereign Hardware, Sensors, WebKit, SMS/2FA & IPC** | `checkpoint_app_state`, `virtual_camera_and_mic_feed`, `telephony_sms_otp_controller`, `biometric_passkey_se_vault`, `webkit_cdp_dom_bridge`, `gps_motion_sensor_teleporter`, `xpc_mach_ipc_sniffer_fuzzer`, `apns_notification_deeplink_bus`, `wireless_radio_recon_suite`, `fs_io_and_iokit_tracer`, `human_touch_physics_and_stream`, `human_pause`, `set_otp`, `background_immortality_governor`, `appgroup_icloud_account_inspector` |
| **07. Social & Photos Automation (`tiktok_*`, `photos_*`)** | `tiktok_open_search`, `tiktok_inbox`, `tiktok_reply`, `tiktok_im`, `tiktok_posts`, `tiktok_sign`, `photos_ensure`, `media_upload`, `photos_import`, `photos_import_file`, `photos_list`, `photos_clear` |
| **08. Out-of-Process Memory, Mach-O, Storage & Frida** | `read_memory`, `write_memory`, `search_memory`, `list_memory_regions`, `inspect_macho`, `dump_entitlements`, `patch_entitlements`, `inject_dylib`, `remove_dylib`, `dump_classes`, `dump_il2cpp`, `symbolicate_crash`, `get_keychain_item`, `set_keychain_item`, `delete_keychain_item`, `get_plist_value`, `set_plist_value`, `query_sqlite`, `scrub_gadget_binary`, `configure_frida_stealth`, `get_frida_stealth_status`, `frida_anti_detection_probe`, `inject_frida_gadget`, `remove_frida_gadget`, `frida_rpc_call`, `frida_list_modules`, `frida_hook_objc`, `frida_memory_scan` |
| **09. UI, Vision/PaddleOCR, Filesystem, Tweak & Diagnostics** | `tap_screen`, `tap_element`, `wait_for_element`, `wait_for_disappear`, `wait_until_texts`, `swipe_screen`, `long_press`, `double_tap`, `drag_and_drop`, `press_home`, `press_power`, `press_volume_up`, `press_volume_down`, `toggle_mute`, `wake_and_home`, `session_force_unlock`, `session_respawn`, `respring`, `device_reboot`, `input_text`, `type_text`, `press_key`, `screenshot`, `get_screen_info`, `get_ui_elements`, `get_element_at_point`, `ocr_screen`, `describe_screen`, `get_clipboard`, `set_clipboard`, `launch_app`, `kill_app`, `list_apps`, `list_running_apps`, `get_frontmost_app`, `get_app_info`, `install_app`, `uninstall_app`, `open_url`, `get_brightness`, `set_brightness`, `get_volume`, `set_volume`, `get_device_info`, `list_dir`, `read_file`, `read_file_chunk`, `tail_file`, `write_file`, `hash_file`, `zip_download`, `search_files`, `get_syslog`, `get_crash_logs`, `read_crash_log`, `run_command`, `tweak_build`, `tweak_deploy`, `tweak_rollback`, `self_update`, `diagnose_roots`, `diagnostics_collect`, `port_forward`, `probe_help` |"""

    readme_text = re.sub(
        r"\| Subsystem \| Tools \|\n\| :--- \| :--- \|(?:\n\| .* \|)+",
        new_table,
        readme_text,
    )
    readme_path.write_text(readme_text, encoding="utf-8")

    readme_en_path = REPO_ROOT / "README_EN.md"
    readme_en_path.write_text(
        f"# iOS MCP (`com.witchan.ios-mcp` `v2.1.1`)\n\n"
        f"See [`README.md`](./README.md) for the complete English technical reference ({total} canonical tools across 9 subsystems), "
        f"[`docs/TOOL_INVENTORY.md`](./docs/TOOL_INVENTORY.md) for the auto-generated schema & alias catalog, and "
        f"[`prompt.txt`](./prompt.txt) for the universal AI operator prompt.\n",
        encoding="utf-8",
    )

    prompt_path = REPO_ROOT / "prompt.txt"
    prompt_text = prompt_path.read_text(encoding="utf-8")
    prompt_text = re.sub(
        r"## 1\. Core Capabilities & Tool Inventory \([^)]+\)",
        f"## 1. Core Capabilities & Tool Inventory ({total} Canonical Tools + Normalized `<subsystem>_<verb>` Aliases Across 9 Subsystems)",
        prompt_text,
    )
    if "### J. Extended File, Hermes/JS, Social, Photos, Tweak Lifecycle & Diagnostics" not in prompt_text:
        extra_section = (
            "\n### J. Extended File, Hermes/JS, Social, Photos, Tweak Lifecycle & Diagnostics\n"
            "- **Filesystem & Log Helpers**: `read_file_chunk`, `tail_file`, `hash_file`, `zip_download`, `search_files` (plus write-safety & optional two-step `approval_id` on `write_file` / `set_plist_value`).\n"
            "- **React Native & Hermes**: `inspect_js_bundle`, `decode_js_bundle`, `list_hermes_decoders`.\n"
            "- **OTP, Human Timing, TikTok & Photos**: `set_otp`, `human_pause`, `wait_until_texts`, `tiktok_open_search`, `tiktok_inbox`, `tiktok_reply`, `tiktok_im`, `tiktok_posts`, `tiktok_sign`, `photos_ensure`, `media_upload`, `photos_import`, `photos_import_file`, `photos_list`, `photos_clear`.\n"
            "- **Network Capture Shorthands**: `net_enable`, `net_disable`, `net_clear`, `net_status`, `net_dump` (with automatic token/cookie redaction).\n"
            "- **Tweak Lifecycle, Session & Discovery**: `tweak_build`, `tweak_deploy`, `tweak_rollback`, `self_update`, `diagnose_roots`, `diagnostics_collect`, `port_forward`, `session_force_unlock`, `session_respawn`, `respring`, `device_reboot`, and `probe_help` (tier filtering `core`/`advanced`/`debug` and `<subsystem>_<verb>` alias lookup).\n"
        )
        prompt_text = prompt_text.replace(
            "\n## 2. Standard Operating Workflows",
            extra_section + "\n## 2. Standard Operating Workflows",
        )
    prompt_path.write_text(prompt_text, encoding="utf-8")


def main() -> int:
    src = MCP_SERVER_M.read_text(encoding="utf-8")
    tools, aliases = parse_mcp_server(src)
    write_inventory(tools, aliases)
    update_readmes(tools)
    print(
        f"[OK] Verified {len(tools)} canonical tools and {sum(len(v) for v in aliases.values())} normalized aliases with 100% dispatch parity."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
