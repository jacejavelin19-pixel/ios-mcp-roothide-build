# iOS MCP (`com.witchan.ios-mcp` `v2.1.1`)

**Sovereign Model Context Protocol (MCP) Server for Autonomous iOS Device Control, Stealth In-Process Instrumentation, Zero-Injection FairPlay Decryption, On-Device ARM64e Decompilation, Anti-Fraud Persona Cloaking, and `MuffinStore` Version Control.**

[![Version](https://img.shields.io/badge/version-2.1.1-blue.svg)](#)
[![Architectures](https://img.shields.io/badge/arch-arm64%20%7C%20arm64e-success.svg)](#)
[![Jailbreaks](https://img.shields.io/badge/jailbreak-RootHide%20%7C%20Rootless%20%7C%20Rootful-purple.svg)](#)
[![MCP Protocol](https://img.shields.io/badge/MCP-2025--11--25-orange.svg)](#)

---

## 1. Overview & System Architecture

`ios-mcp` (`v2.1.1`) embeds a high-privilege JSON-RPC 2.0 Model Context Protocol server directly into `SpringBoard` (`:8090/mcp`), backed by a modular suite of out-of-process Mach/root helper binaries and a custom Frida-free in-process instrumentation engine (`libmcpengine.dylib`).

Every subsystem is engineered for **iOS 15.0 – 18.5+ (`arm64` Rootless & `arm64e` RootHide)** under strict `pmap_cs`, PAC (Pointer Authentication), and TPRO (`__DATA_CONST` / `__AUTH_CONST` hardware write-protection) enforcement:

- **Zero `__TEXT` Code Patching**: Native C/system hooks operate exclusively via data-only GOT/lazy-pointer rebinding (`__got`, `__la_symbol_ptr`, `__auth_got`, `__auth_ptr`) with in-process PAC IA/IB signing (`engine_prepare_native_hook`) and transparent out-of-process `mach_vm_protect` copy-on-write promotion (`mcp-memory patch-slots`), or via CPU hardware debug registers (`DBGBVR0..15` / `DBGBCR0..15` + Mach exception ports).
- **Zero `RWX` Anonymous Memory**: `libmcpengine.dylib` contains zero Frida/Gum code and never allocates `VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE` pages.
- **Zero In-App TCP Listeners**: Communication between `SpringBoard` and injected target apps uses a sandbox-local Unix domain socket (`<DataContainer>/tmp/.mcpe.sock`).

```text
ios-mcp (v2.1.1 Master Architecture — 193 Tools Across 9 Subsystems)
├── 01. CORE DAEMON & PRIVILEGE LAYER
│   ├── ios-mcp.dylib (SpringBoard resident HTTP/JSON-RPC MCP Server :8090)
│   ├── mcp-helperd (KeepAlive LaunchDaemon -> /var/mobile/Library/Caches/ios-mcp-work/.helperd.sock)
│   ├── mcp-root (Setuid 04755 root escalation gate with strict allowlist)
│   └── DEBIAN Lifecycle (postinst, prerm, postrm — zero-residue package uninstall)
│
├── 02. STEALTH IN-PROCESS ENGINE (libmcpengine.dylib + libmcp_stealth.dylib)
│   ├── Injection Modes (mcp-appmod): lc_load_dylib + RootHide TweakInject (00_fridastealth + 01_libmcpengine)
│   ├── ObjC Runtime Instrumentation (engine_classes, engine_describe_class, engine_hook_objc, engine_invoke)
│   ├── Data-Only PAC/TPRO Native GOT Hooking (engine_prepare_native_hook, engine_hook_native, engine_call)
│   ├── In-Process Memory & Transport Capture (engine_read/write/search_memory, BoringSSL SSL_read/SSL_write)
│   └── Specialized Modules (engine_re, engine_crypto, engine_antifraud, engine_webview, engine_media_bio)
│
├── 03. DECRYPTION, DECOMPILATION & CROSS-PLATFORM RE
│   ├── Zero-Injection Out-of-Process FairPlay Decryptor & Clean .ipa Builder (decrypt_app_ipa)
│   ├── Built-In ARM64e PAC-Aware Disassembler, Xref Walker & Pseudo-C Lifter (decompile_function, decompile_objc_method, find_xrefs_to)
│   ├── Zero-Memory-Patch ARM64 Hardware Breakpoints (hardware_breakpoint_hook via DBGBVR/DBGBCR)
│   └── Swift 5 Metadata, dyld_shared_cache, React Native Hermes & Flutter AOT Extractors
│
├── 04. NETWORK, QUIC/HTTP3, PROTOBUF & CRYPTO HARVESTER
│   ├── Universal HTTP/HTTPS, NSURLSession & BoringSSL Plaintext Capture
│   ├── CommonCrypto, SecKey & BoringSSL EVP Key/IV/Plaintext Harvester (trace_crypto_primitives, get_crypto_events)
│   ├── Network.framework QUIC/HTTP3 & WebSocket Interceptor + Schema-Less Protobuf Decoder (hook_quic_http3, decode_protobuf)
│   └── Native In-App NSURLSession JA3/JA4 & HTTP/2 Replay (replay_request_native, tls_ja3_ja4_http2_cloak)
│
├── 05. 12-LAYER ANTI-FRAUD & BOT-DEFENSE SDK BYPASS MATRIX
│   ├── Data-Only Syscall Shield & Inline SVC #0x80 Scanner/Hardware Trap (stealth_syscall_shield)
│   ├── Device Fingerprint Chameleon & Virtual Keychain Isolator (spoof_device_fingerprint, sync_fraud_persona)
│   ├── Process/Thread/IMP/dladdr/VPN Cloaks (kernel_proc_cloak, proxy_vpn_network_cloak, objc_swizzle_and_dladdr_integrity_cloak, thread_mach_port_and_stack_cloaker)
│   ├── Bot & Risk SDK Neutralizers (PerimeterX, Akamai BMP, DataDome, Kasada, ThreatMetrix, Sardine, Forter, SEON, App Attest)
│   └── 7-Vector Canary Wiper, One-Click Persona Orchestrator & 50-Point Live Self-Auditor (wipe_fraud_canaries, apply_fraud_persona, audit_fraud_surface)
│
├── 06. AUTONOMOUS APP STORE & MUFFINSTORE VERSION CONTROL (mcp-appstore)
│   ├── App Store Search, adamId Resolver & appExtVrsId Catalog (appstore_search_and_versions)
│   ├── Headless Zero-UI App Store Acquisition & Installer (appstore_install)
│   ├── Historical Version Downgrader via buyParameters appExtVrsId Injection (appstore_downgrade)
│   └── Automated Multi-Version Rollback & Security-Hardening Diff Pipeline (appstore_auto_rollback_diff)
│
└── 07. SOVEREIGN HARDWARE, SENSORS, WEBKIT DOM, SMS/2FA & SYSTEM IPC
    ├── Sandbox + Keychain Snapshot, Diff & Rollback (checkpoint_app_state)
    ├── Virtual Camera QR/Frame & AudioUnit PCM Microphone Feed (virtual_camera_and_mic_feed)
    ├── Real-Time SMS/iMessage 2FA OTP Watcher & CoreTelephony Controller (telephony_sms_otp_controller)
    ├── Headless FaceID/TouchID (LAContext) & WebAuthn Passkey Vault (biometric_passkey_se_vault)
    ├── Live In-App WKWebView JS Evaluator, DOM Screen-Rect Dumper & Cookie Extractor (webkit_cdp_dom_bridge)
    ├── GPS Trajectory Simulator, XPC Sniffer, APNs Push Forger, Radio Recon, Undelete File Quarantine, Fitts's Law Touch & MJPEG Streamer
```

---

## 2. Quick-Start & AI Agent Setup

### Instant AI Agent Onboarding (`prompt.txt`)
Copy the contents of [`prompt.txt`](./prompt.txt) in the repository root into your AI coding agent (Claude Code, Cursor, Codex, Grok, or custom MCP client) to give it complete operational knowledge of all `v2.1.1` tools and standard workflows.

### MCP Server Registration
```json
{
  "mcpServers": {
    "ios-mcp": {
      "type": "streamable-http",
      "url": "http://<DEVICE_LAN_IP_OR_127.0.0.1>:8090/mcp"
    }
  }
}
```
For USB port forwarding via `iproxy`:
```bash
iproxy 18090 8090
```

### HTTP Endpoints (`:8090`)
| Endpoint | Method | Description |
| :--- | :---: | :--- |
| `/mcp` | `POST` | JSON-RPC 2.0 MCP endpoint (`initialize`, `tools/list`, `tools/call`, `ping`). |
| `/health` | `GET` | Liveness and version check (`{"status":"ok","server":"ios-mcp","version":"2.1.1",...}`). |
| `/stream.mjpeg` | `GET` | Real-time multipart MJPEG screen stream (`?fps=15&quality=0.65&max_frames=300`). |
| `/upload_file` | `POST` | Streams large binary uploads (`.ipa`, `.tipa`, `.deb`, media) to `/var/mobile/Library/Caches/ios-mcp-uploads/`. |
| `/download_file` | `GET` | Streams arbitrary device files (`?path=/tmp/decrypted.ipa`) with root fallback. |

---

## 3. Consolidated Tool Reference (`v2.1.1`)

| Subsystem | Tools |
| :--- | :--- |
| **01. Stealth In-Process Engine (`libmcpengine`)** | `engine_inject`, `engine_remove`, `engine_ping`, `engine_modules`, `engine_classes`, `engine_describe_class`, `engine_hook_objc`, `engine_hook_events`, `engine_unhook`, `engine_invoke`, `engine_get_ivar`, `engine_set_ivar`, `engine_prepare_native_hook`, `engine_hook_native`, `engine_start_capture`, `engine_get_requests`, `engine_stop_capture`, `engine_call`, `engine_read_memory`, `engine_write_memory`, `engine_search_memory`, `engine_eval_js`, `engine_hw_breakpoint`, `engine_decompile`, `engine_trace_crypto`, `engine_get_crypto_events`, `engine_stop_crypto`, `engine_hook_quic_http3`, `engine_decode_protobuf`, `engine_replay_request` |
| **02. Decryption, Decompilation, Hermes/JS & Swift RE** | `decrypt_app_ipa`, `decompile_function`, `decompile_objc_method`, `find_xrefs_to`, `hardware_breakpoint_hook`, `dump_swift_metadata`, `extract_dyld_shared_cache`, `inspect_hermes_flutter`, `inspect_js_bundle`, `decode_js_bundle`, `list_hermes_decoders` |
| **03. Network, QUIC/HTTP3, Protobuf & Crypto Capture** | `start_capture`, `stop_capture`, `get_captured_requests`, `net_enable`, `net_disable`, `net_clear`, `net_status`, `net_dump`, `bypass_pinning`, `restore_pinning`, `trace_crypto_primitives`, `get_crypto_events`, `hook_quic_http3`, `decode_protobuf`, `replay_request_native`, `tls_ja3_ja4_http2_cloak` |
| **04. Anti-Fraud SDK Bypass, Cloaking & Persona Suite** | `stealth_syscall_shield`, `spoof_device_fingerprint`, `kernel_proc_cloak`, `proxy_vpn_network_cloak`, `hardware_canvas_gpu_audio_randomizer`, `behavioral_biometrics_ghost_player`, `perimeterx_akamai_datadome_kasada_tap`, `threatmetrix_sardine_forter_seon_neutralizer`, `apple_app_attest_devicecheck_bridge`, `sync_fraud_persona`, `objc_swizzle_and_dladdr_integrity_cloak`, `thread_mach_port_and_stack_cloaker`, `wipe_fraud_canaries`, `apply_fraud_persona`, `audit_fraud_surface` |
| **05. App Store & `MuffinStore` Version Control** | `appstore_search_and_versions`, `appstore_install`, `appstore_downgrade`, `appstore_auto_rollback_diff` |
| **06. Sovereign Hardware, Sensors, WebKit, SMS/2FA & IPC** | `checkpoint_app_state`, `virtual_camera_and_mic_feed`, `telephony_sms_otp_controller`, `biometric_passkey_se_vault`, `webkit_cdp_dom_bridge`, `gps_motion_sensor_teleporter`, `xpc_mach_ipc_sniffer_fuzzer`, `apns_notification_deeplink_bus`, `wireless_radio_recon_suite`, `fs_io_and_iokit_tracer`, `human_touch_physics_and_stream`, `human_pause`, `set_otp`, `background_immortality_governor`, `appgroup_icloud_account_inspector` |
| **07. Social & Photos Automation (`tiktok_*`, `photos_*`)** | `tiktok_open_search`, `tiktok_inbox`, `tiktok_reply`, `tiktok_im`, `tiktok_posts`, `tiktok_sign`, `photos_ensure`, `media_upload`, `photos_import`, `photos_import_file`, `photos_list`, `photos_clear` |
| **08. Out-of-Process Memory, Mach-O, Storage & Frida** | `read_memory`, `write_memory`, `search_memory`, `list_memory_regions`, `inspect_macho`, `dump_entitlements`, `patch_entitlements`, `inject_dylib`, `remove_dylib`, `dump_classes`, `dump_il2cpp`, `symbolicate_crash`, `get_keychain_item`, `set_keychain_item`, `delete_keychain_item`, `get_plist_value`, `set_plist_value`, `query_sqlite`, `scrub_gadget_binary`, `configure_frida_stealth`, `get_frida_stealth_status`, `frida_anti_detection_probe`, `inject_frida_gadget`, `remove_frida_gadget`, `frida_rpc_call`, `frida_list_modules`, `frida_hook_objc`, `frida_memory_scan` |
| **09. UI, Vision/PaddleOCR, Filesystem, Tweak & Diagnostics** | `tap_screen`, `tap_element`, `wait_for_element`, `wait_for_disappear`, `wait_until_texts`, `swipe_screen`, `long_press`, `double_tap`, `drag_and_drop`, `press_home`, `press_power`, `press_volume_up`, `press_volume_down`, `toggle_mute`, `wake_and_home`, `session_force_unlock`, `session_respawn`, `respring`, `device_reboot`, `input_text`, `type_text`, `press_key`, `screenshot`, `get_screen_info`, `get_ui_elements`, `get_element_at_point`, `ocr_screen`, `describe_screen`, `get_clipboard`, `set_clipboard`, `launch_app`, `kill_app`, `list_apps`, `list_running_apps`, `get_frontmost_app`, `get_app_info`, `install_app`, `uninstall_app`, `open_url`, `get_brightness`, `set_brightness`, `get_volume`, `set_volume`, `get_device_info`, `list_dir`, `read_file`, `read_file_chunk`, `tail_file`, `write_file`, `hash_file`, `zip_download`, `search_files`, `get_syslog`, `get_crash_logs`, `read_crash_log`, `run_command`, `tweak_build`, `tweak_deploy`, `tweak_rollback`, `self_update`, `diagnose_roots`, `diagnostics_collect`, `port_forward`, `probe_help` |

---

## 4. Building & Packaging

### Automated CI Build (`roothide-tweak-build.yml`)
Pushing to `chore-roothide-toolchain` runs the GitHub Actions pipeline on `macos-15` using RootHide Theos + iPhoneOS 16.5 SDK, compiling all helpers, standalone Apple-SDK payloads (`arm64` + `arm64e`), and packaging both:
- `packages/com.witchan.ios-mcp_2.1.1_iphoneos-arm64.deb` (Rootless)
- `packages/com.witchan.ios-mcp_2.1.1_iphoneos-arm64e.deb` (RootHide)

### Local Build (`./build.sh`)
```bash
chmod +x build.sh
./build.sh
```

---

## 5. Clean Uninstall Guarantee (`DEBIAN/prerm` & `DEBIAN/postrm`)

Uninstalling `com.witchan.ios-mcp` via Sileo, Zebra, or `dpkg -r` / `dpkg -P` automatically:
1. Stops and unloads the `com.witchan.ios-mcp.helperd` LaunchDaemon.
2. Sweeps all installed user apps via `mcp-appmod` to revert any active `LC_LOAD_DYLIB` or `TweakInject` instrumentation and restore original binaries and code signatures.
3. Cleans runtime sockets, temporary staging directories, checkpoints, and spoof profiles while preserving user-cached Frida gadget binaries.

---

## 6. License

Licensed under the [Apache License 2.0](./LICENSE). Third-party notices and component licenses are documented in [`NOTICE`](./NOTICE) and [`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md).
