# OCR 双引擎开发测试记录（2026-09-25，未发版）

本页保留最初 222 动态运行库构建的测试数据及包哈希，不代表之后所有构建。
后续 221（iOS 14.3 / rootful）的静态链接修复与回归见
[兼容性补测记录](PADDLEOCR_TEST_RESULTS.md)。223 也已用之前的动态运行库
构建完成专项补测。随后三台设备均已安装新构建的静态链接正式模式包，并完成
第三方应用 OCR 专项测试；最新覆盖、识别误差与边界限制见
[三设备测试报告](PADDLEOCR_TEST_RESULTS.md)。
之后又完成了 [iOS 13.5.1 真机补测](PADDLEOCR_TEST_RESULTS.md)，本页原始 iOS 13 未验证状态不代表最新进展。

## 结论与边界

实现了请求级 `engine` 选择、Vision 保留、PaddleOCR 原生 CPU worker、打包和可执行测试。
未改版本号，仍为 1.2.6；没有执行 git add/commit/push、创建分支、tag 或发布。
新增依赖按 iOS 13.0 构建，不等于已完成 iOS 13 运行验收。

**尚未完成 iOS 13 真机验证**。本页最初测试时 221 不在线，223 尚未安装当时的包；
后续验证范围见上方补测记录。缺少 iOS 13 设备的四项重点验收
（默认 Vision 英文、显式 Vision 英文、Vision 中文明确报错、Paddle 中英数字）
全部标记 SKIP，不把较新设备或宿主机结果冒充旧系统结果。

实际安装并测试：192.168.1.222，iPhone 7 / iPhone9,3 / A10 / iOS 15.8.8，
roothide，375×667 固定屏幕点，750×1334 截图像素。模型不需要联网推理。

## 依赖与兼容性证据

- ONNX Runtime 1.20.1，从锁定源码构建，CPUExecutionProvider 唯一提供者。
  [官方该版本 iPhone 构建配置](https://github.com/microsoft/onnxruntime/blob/v1.20.1/tools/ci_build/github/apple/default_full_ios_framework_build_settings.json)
  使用 iOS 13.0；本项目明确关闭 CoreML/XNNPACK，不沿用 iOS 15 的预编译包。
- PP-OCRv5_mobile 官方 PaddlePaddle ONNX 导出，检测模型 IR 6/opset 11、
  识别模型 IR 3/opset 7、float32、CTC 18,385 类；没有改写模型声明。
  通过 ONNX checker，以及 Mac 和真机的实际模型加载/原生推理。
- OpenCV 4.10.0 core/imgproc、Clipper 6.4.2、锁定 Eigen 提交。
  完整下载 URL、revision、SHA256 与许可证见 `third_party/paddleocr/`。
- 实际 Mach-O 检查：worker 和 ORT 均 arm64、minos=13.0；
  两个 OpenCV 静态库的成员也为 iOS 13.0。全量 undefined symbols 已留档。
  ORT 的 filesystem 依赖在 [Apple 的支持表](https://developer.apple.com/xcode/cpp/)中最低为 iOS 13.0。
  未使用真实 iOS 13 dyld cache 做完整符号解析，仍需旧系统真机验收。
- worker/ORT 无 Vision、CoreML、Metal、Neural Engine 动态链接；
  worker 初始化时硬性检查可用 EP 只有 CPU。SpringBoard 主 dylib 不链接 ORT/OpenCV。
  `recognition.provider` 和日志同时确认实际分支。
- 三个 deb 都解包核对了目录前缀、模型/字典 SHA256、许可证、
  worker/runtime 的架构/minos/链接依赖，不只检查 staging 目录。
- 原有非 OCR 的 `mcp-ldid` 仍静态链接带 iOS 15 对象版本的 libcrypto，
  rootful 构建会提示版本不匹配；既有 arm64e/旧链接参数/libzip 警告也仍存在。
  新 OCR 不链接该 helper/libcrypto，但不能因此声称整个安装包所有旧功能已在 iOS 13 验证。

## 功能与隔离验收

| 测试 | 结果 | 实际观察 |
|---|---|---|
| 旧调用省略 engine | PASS | Vision；原参数/结果坐标保留 |
| 显式 vision | PASS | Vision |
| 显式 paddleocr | PASS | 原生 ORT CPU，中英数字识别；非 Vision 代理 |
| Paddle 后省略 engine | PASS | 回到 Vision，无全局偏好 |
| 两引擎实际并发 | PASS | 各自返回正确引擎，无串用 |
| 两个 Paddle 并发 | PASS | 一条执行，另一条明确 busy，不排队积压 |
| 非法 engine | PASS | 两个工具均对 8 类非法值返回 -32602 |
| describe_screen | PASS | 两引擎 OCR 层；保持原部分结果/ocr_error 约定 |
| 真机模型缺失 | PASS | Paddle 明确 missing；同时 Vision 仍识别出 23 段文字；恢复资源后恢复 |
| 损坏模型/非法图像 | PASS（Mac 原生 worker） | 明确校验失败/解析失败，不回退；后续有效请求恢复 |
| 会话复用 | PASS | 连续请求 worker PID 不变 |
| 请求取消 | PASS | 只终止对应 worker，确认 PID 不再存在，随后两引擎正常 |
| 30 秒超时 | PASS | 人为暂停确切 worker 后约 30.04 秒返回错误，worker 被杀并回收 |
| HTTP 断连 | PASS | 终止 worker，后续重新初始化成功 |
| 默认/并发路由单元测试 | PASS | 生产 router + 引擎替身，200 并发调用；不冒充真实推理 |
| 取消上下文单元测试 | PASS | session、字符串/数字 ID、重复 ID、断连、deadline、清理 |
| 中英数字/方向/ROI 真机 UI | PASS | 竖屏、左横屏、右横屏；两引擎各 3 次全屏 tap + 1 次 ROI tap，共 24 次全部命中 |
| 四方向原生 fixture | PASS | 1/3/6/8 图像方向，含倒置图像；准确文字与已知框中心校验 |
| CTC 置信度阈值 | PASS（Mac + 真机原生 worker） | 0 与 0.99 的过滤按未舍入的平均 CTC 概率验证；不与 Vision 置信度直接等价 |
| 长时间压力、极端 jetsam、Display Zoom | SKIP | 未做长期压力/系统配置变更，不声明覆盖 |
| iOS 13/14/18 本次包运行 | SKIP | 只有上述 iOS 15.8.8 真机计入通过 |

UI 测试由本机提供纯文字按钮页面，真实截图→实际 OCR→MCP tap→页面回传命中的按钮 ID。
Frida 只用于旋转界面和临时防休眠，不修改 OCR/截图/HID 的实现；测试后恢复方向、
旋转锁与 idle timer，返回主屏幕。倒置方向只有原生 fixture 验证，没有 iPhone 倒置 UI 验证。

取消按请求携带的 session header + typed ID 匹配。现有 MCP 服务给客户端返回共享
session token；共享此 token 的客户端需要避免复用尚未结束的请求 ID。此次未重写会话系统。

## MCP 引擎专项（最终安装包）

耗时仅为该设备/页面的一次实测，不代表通用性能保证。Paddle 冷启动约 3.20 秒、
复用约 2.74 秒、单行 ROI 约 0.43 秒；Vision 该页面约 1.75 秒。

| 用例 | 状态 | 秒 |
|---|---|---:|
| legacy-default | PASS | 1.765 |
| explicit-vision | PASS | 1.746 |
| paddle-cold | PASS | 3.200 |
| paddle-warm | PASS | 2.743 |
| default-after-paddle | PASS | 1.693 |
| ocr_screen-invalid-'other' | PASS | 0.013 |
| describe_screen-invalid-'other' | PASS | 0.012 |
| ocr_screen-invalid-'' | PASS | 0.012 |
| describe_screen-invalid-'' | PASS | 0.013 |
| ocr_screen-invalid-'VISION' | PASS | 0.013 |
| describe_screen-invalid-'VISION' | PASS | 0.012 |
| ocr_screen-invalid-None | PASS | 0.011 |
| describe_screen-invalid-None | PASS | 0.011 |
| ocr_screen-invalid-1 | PASS | 0.012 |
| describe_screen-invalid-1 | PASS | 0.012 |
| ocr_screen-invalid-True | PASS | 0.011 |
| describe_screen-invalid-True | PASS | 0.011 |
| ocr_screen-invalid-[] | PASS | 0.011 |
| describe_screen-invalid-[] | PASS | 0.010 |
| ocr_screen-invalid-{} | PASS | 0.012 |
| describe_screen-invalid-{} | PASS | 0.011 |
| paddle-roi | PASS | 0.433 |
| vision-empty-roi | PASS | 0.014 |
| paddleocr-empty-roi | PASS | 0.014 |
| concurrent-vision | PASS | 2.187 |
| concurrent-paddleocr | PASS | 3.365 |
| describe-paddleocr | PASS | 3.049 |
| describe-vision | PASS | 1.963 |
| paddle-language-error-no-fallback | PASS | 0.013 |

## 完整 MCP 回归：222

按 ios-mcp-test 的先构建/安装/全量验证流程执行。最终稳定运行后的脚本汇总：
PASS 46 / FAIL 0 / SKIP 0。

注意：`input_text/type_text/press_key` 是脚本合并行；
输入内容通过 OCR 校验，`press_key delete` 的实际删除效果仍未确认，不能将其单独当作验证通过。
安装/卸载两行是错误输入 wiring 检查，不是新 IPA 的安装卸载往返；
本次 deb 的实际安装另外已经执行并确认。

| 功能点 | 状态 | 详情 |
|---|---|---|
| `HTTP /health` | PASS | ios-mcp 1.2.6 status=ok |
| `HTTP upload+download` | PASS | roundtrip 20b ok |
| `get_screen_info` | PASS | 375x667pt locked=False |
| `get_device_info` | PASS | iPhone9,3 iOS 15.8.8 batt 99% |
| `get_frontmost_app` | PASS | com.apple.springboard |
| `describe_screen` | PASS | 32 elements |
| `get_ui_elements` | PASS | 5 elems |
| `get_element_at_point` | PASS | hit-test ok |
| `ocr_screen` | PASS | 33 texts |
| `screenshot` | PASS | 76346b jpeg |
| `get_brightness` | PASS | 0.231 |
| `get_volume` | PASS | 0.125 |
| `get_clipboard` | PASS | has clipboard |
| `list_apps` | PASS | 14 apps |
| `list_running_apps` | PASS | 1 running |
| `get_app_info` | PASS | com.Alfie.TrollInstallerX.CFK4B4MHGY v1 |
| `list_dir` | PASS | 5 entries |
| `write_file` | PASS | 17 bytes |
| `read_file` | PASS | content matches |
| `run_command` | PASS | MCP_OK_42 |
| `get_crash_logs` | PASS | 30 reports |
| `read_crash_log` | PASS | 30032 chars |
| `get_syslog` | PASS | 0 error entries / 3s |
| `set_clipboard` | PASS | roundtrip ok (restored) |
| `set_brightness` | PASS | set 0.9 -> 0.9 (restored) |
| `set_volume` | PASS | set 0.9 -> 0.9 (restored) |
| `install_app(wiring)` | PASS | rejected bad path -> wired (File not found: /var/mobile/__nope__.ipa) |
| `uninstall_app(wiring)` | PASS | rejected bogus id -> wired (Uninstall failed: DEB package not installed: com.example.doe) |
| `wake_and_home` | PASS | locked=False on=True |
| `press_home` | PASS | Home button pressed (100ms) -> SpringBoard |
| `press_volume_up` | PASS | Volume Up button pressed (100ms) |
| `press_volume_down` | PASS | Volume Down button pressed (100ms) |
| `toggle_mute` | PASS | toggled twice (restored) |
| `tap_screen` | PASS | Tapped at (1.0, 1.0) |
| `tap_element` | PASS | matched & tapped '飞行模式' |
| `long_press` | PASS | Long pressed at (1.0, 1.0) for 500ms |
| `double_tap` | PASS | Double tapped at (1.0, 1.0) with 100ms interval |
| `swipe_screen` | PASS | Swiped from (200.0,500.0) to (200.0,200.0) in 300ms |
| `drag_and_drop` | PASS | scrolled (content changed) |
| `wait_for_element` | PASS | found=False waited=2.1s |
| `wait_for_disappear` | PASS | disappeared=True |
| `launch_app` | PASS | frontmost=com.apple.Preferences |
| `kill_app` | PASS | killed (not frontmost) |
| `open_url` | PASS | opened Settings (frontmost=com.apple.Preferences) |
| `input_text/type_text/press_key` | PASS | input+type OCR=ok, press_key delete=unverified |
| `press_power` | PASS | on=True -> press_power on=False -> wake on=True |

## 构建产物

这些是本地开发验证包，不是新版本发布；所有包保留原来的 1.2.6 版本号。

- `com.witchan.ios-mcp_1.2.6_iphoneos-arm.deb`: 23953406 bytes; SHA256 `196ea8c0a458fd4acfce919b10a1d2088cd805e94122c36be67129b18f5f1890`
- `com.witchan.ios-mcp_1.2.6_iphoneos-arm64.deb`: 23893458 bytes; SHA256 `f83bd39cd7b17c474b18f0e07067cfdd4dbc81d2c946875807f788ada1eec7a8`
- `com.witchan.ios-mcp_1.2.6_iphoneos-arm64e.deb`: 23892610 bytes; SHA256 `6e2054370722b0e86d9bceb957b47448543e1432b89d81865862025e239cfd34`

## 复现方式与证据

完整命令见 [PADDLEOCR.md](PADDLEOCR.md)。入口：

- `scripts/test_ocr_unit.sh`
- `tests/paddle_worker_test.py`（Mac 或 SSH 真机原生 worker）
- `tests/mcp_ocr_engines_test.py`
- `tests/paddle_lifecycle_device_test.py`（仅授权设备，故障注入后 finally 恢复模型）
- `tests/ocr_ui_device_test.py`（真实界面/横屏/点击）
- `tests/paddle_package_test.py`
- `.codex/skills/ios-mcp-test/scripts/test_ios_mcp.py`

本地原始证据位于 `.codex-session-data/paddle-build/`，不纳入 Git：
`binary-audit.json`、`package-audit.json`、`final-package-{1,2,3}.log`、
`final-engines222.json`、`final-lifecycle222.json`、`final-ui222/results.json`、
`final-native-macos.json`、`final-native222.json`、`final-full222-stable.log`。

测试期间排除的无效轮次也保留：初次 skill 安装被锁屏拦截，但旧版本号相同，
不能用健康检查的版本号宣称装上新代码；最后一次安装后立即测试又撞到异步 respring
窗口。新增安装测试脚本会检查安装返回错误，并等待新 SpringBoard PID，
避免将旧进程的短暂 /health 响应当成安装完成。

实际发现并修正的新增实现问题：CGImage 解码不应多做垂直翻转；
SpringBoard 对 Unix socket 的 poll 返回 EPERM 时使用有界 select；
spawn 源 FD 避开 0/1/2；成功请求的旧初始化警告不带入后续取消错误。


---

# 默认 OCR 引擎改为 PaddleOCR（2026-09-26）

## 本次变更

按用户最新要求，省略 `engine` 时由 Vision 改为 **PaddleOCR + ONNX Runtime CPU**。
显式 `engine="vision"` 保留 Apple Vision，显式 `engine="paddleocr"` 保持不变。
选择仍只影响当前请求；不会保存上次引擎、创建偏好设置或在失败时自动换引擎。
非法 engine（包括空字符串、JSON null、错误类型）仍返回参数错误。

- `OCRManager.h/.m`：固定 `defaultEngine` 为 paddleocr，实际执行和旧 native 重载都使用它。
- `MCPServer.m`：两工具 Schema 和描述同步；取消/断连上下文也通过同一默认值解析。
  `describe_screen` 只有确实启用 `include_ocr` 时才创建 OCR 请求上下文，默认仍不做 OCR。
- `README.md`、`README_EN.md`、`docs/PADDLEOCR.md`：同步默认值与显式 Vision 调用方式。
- 测试脚本：默认值断言改为 Paddle，故障隔离中的 Vision 请求改为显式选择；
  生命周期脚本新增 `--omit-engine` 和 `--fault-tool`，可以验证两个工具的默认路径。

这是有意的默认行为变化，不是只改 Schema：原先不传 engine 的调用现在会加载 Paddle
模型，受其并发/资源上限约束；模型缺失时该请求报错，不静默切回 Vision。
Vision 的语言支持、revision、fast/accurate 与 CPU-only accurate 实现均未改动。
模型、运行库、OCR 阈值、坐标映射也未改动；已有窄 ROI 漏检和超长行限制没有因此修复。

## 调用

以下是 `tools/call` 的 params：

```json
{"name":"ocr_screen","arguments":{}}
{"name":"ocr_screen","arguments":{"engine":"paddleocr"}}
{"name":"ocr_screen","arguments":{"engine":"vision","languages":["en-US"]}}
{"name":"describe_screen","arguments":{"include_ocr":true}}
```

第一、二、四种使用 PaddleOCR，第三种使用 Vision。显式 Vision 调用之后再省略 engine，
仍回到 PaddleOCR。`describe_screen` 不启用 `include_ocr` 时依然没有 OCR 层。

## 构建与安装

按 ios-mcp-test 的先构建、安装、实际测试流程执行，限定本次 OCR 改动范围。
本次设备为 `192.168.1.17`，iPhone 7 Plus / iOS 13.5.1 / rootful，使用第三方 Cydia 页面。
构建使用 `printf '1\n1\n' | ./build.sh`，正式模式 `FINALPACKAGE=1 DEBUG=0 STRIP=1`。
通过 MCP 上传并安装，等到新的 SpringBoard PID 和工具 Schema 才开始测试。

本次 rootful 包仍为本地未发布的 1.2.6，23,653,312 字节：
`packages/com.witchan.ios-mcp_1.2.6_iphoneos-arm.deb`。
SHA256：`8c3f61915399d6f523b874b46d456212b451cb4eee54b5f9a5015268a5aa4456`。
实际 deb 的模型/字典/许可证/架构/链接审计通过；worker、ORT/OpenCV 均为 arm64、minos=13.0。
本次仅重打 rootful，未重打 rootless/roothide，也未更新 221/222/223。
未修改版本号、提交、推送或发布。先前同名 rootful 包保存在本轮 `previous-rootful.deb`。

路由单元测试验证实际 production router，识别本身用引擎替身，不冒充真机推理；
包含 nil 默认值、旧 native 方法、显式两引擎、非法参数、默认失败不回退和 200 次并发。
取消上下文单元测试验证 session/typed ID、重复 ID、deadline 和清理；均通过。

## 真机结果

本轮 192.168.1.17 的 84 个检查项最终通过：引擎测试 32 项、iOS 13 兼容性 38 项、
两工具的默认引擎生命周期各 7 项。使用 Cydia 第三方应用，不使用系统应用作为 OCR 样本。

| 功能点 | 状态 | 实际检查 |
| --- | --- | --- |
| `ocr_screen` 省略 engine/arguments | PASS | 实际返回 paddleocr、CPUExecutionProvider，不只检查 Schema |
| 显式 Vision / PaddleOCR | PASS | 各自执行；Vision 后、Paddle 后省略 engine 均返回 Paddle |
| 两引擎并发 | PASS | 引擎不串用；Paddle 忙时显式 Vision 仍有文本结果 |
| 非法 engine / 参数 | PASS | 参数错误，未静默改引擎 |
| `describe_screen(include_ocr=true)` | PASS | 省略 engine 为 Paddle；显式引擎路由正常 |
| `describe_screen` 不启用 OCR | PASS | 没有 OCR 结果层 |
| iOS 13 Vision 语言 / 模式 | PASS | revision 1；默认英文及显式英文正常，显式中文报不支持 |
| 默认 Paddle 中英文与数字 | PASS | fast/accurate 提示均使用固定 mobile 模型，返回对应文字 |
| ROI / 坐标边界 / JPEG | PASS | 两引擎 ROI、非法及超界区域、截图点尺寸检查通过 |
| 两工具默认请求模型缺失 | PASS | 明确 Paddle 错误，无回退；Vision 可用；恢复模型后 Paddle 恢复 |
| 两工具默认请求取消 / session 隔离 | PASS | 正确 session 取消会结束 worker；其他 session 不误取消 |
| 两工具默认请求超时 | PASS | ocr_screen 30.04 秒、describe_screen 30.99 秒返回；确认对应 worker 已退出 |
| 两工具默认请求 HTTP 断连 | PASS | 对应 worker 退出，后续两引擎恢复 |
| 安装与故障注入恢复 | PASS | 主 dylib、worker、两模型及字典的设备 SHA256 与 deb 完全相同，无测试备份残留 |
| 221 / 222 / 223、本轮横屏与点击命中 | SKIP | 本次仅更改默认路由，未重跑这些设备和交互；不能拿此前构建结果冒充本轮结果 |

`describe_screen` 首次故障测试在恢复模型的 SSH 命令上退出 255；已保留失败日志，
重新连通后检查并恢复 `rec.onnx`，随后完整重跑该组 7 项通过。没有将这次基础设施失败
算作首次通过，也没有修改产品逻辑绕过测试。最终模型完整性验证通过。

最终显式 Vision 返回 `engine=vision, revision=1, languages=[en-US]`；随后无 engine 请求
返回 `engine=paddleocr, provider=CPUExecutionProvider, runtime=onnxruntime-1.20.1,
model=PP-OCRv5_mobile, uses_cpu_only=true`。测试结束已返回桌面，SpringBoard PID 为 2973。
这是 iOS 13.5.1 的运行证据，不等同于对 iOS 13.0 或全部应用的识别准确率作保证。

## 复跑

```sh
bash scripts/test_ocr_unit.sh
python3 tests/mcp_ocr_engines_test.py --url http://192.168.1.17:8090/mcp --out engines.json
python3 tests/ocr_ios13_device_test.py --url http://192.168.1.17:8090/mcp --out ios13.json
SSHPASS=YOUR_TEST_DEVICE_PASSWORD python3 tests/paddle_lifecycle_device_test.py \
  --url http://192.168.1.17:8090/mcp --ssh root@192.168.1.17 \
  --resources /usr/share/ios-mcp/paddleocr --app-bundle-id com.saurik.Cydia \
  --omit-engine --fault-tool ocr_screen --out lifecycle-ocr.json
# 再将 --fault-tool 改为 describe_screen，检查其 include_ocr=true 的默认路径。
```

原始日志目录：`.codex-session-data/ocr-default-paddle.jRglzK/`。
此前三设备和 iOS 13.5.1 的报告记录的是 Vision-default 构建，历史数据保留不回写。


---

# iOS 13.5.1 真机 OCR 补测（2026-09-26）

历史构建记录：本页对应“默认 Vision”的包与测试。之后按用户要求改为默认 PaddleOCR，
最新默认行为与验证见 [默认引擎变更报告](PADDLEOCR_TEST_RESULTS.md)，本页原始结果不回写。

## 设备与构建

- 地址：`192.168.1.17`；iPhone 7 Plus / iPhone9,2 / A10 / iOS 13.5.1（17F80）。
- 越狱：rootful；原安装 iOS MCP 1.0.1，本次升级为当前工作区的 1.2.6 正式模式包。
- 根据 ios-mcp-test 流程先构建、审计、安装、确认新进程和接口，再做实际 OCR 验证。
  原 1.0.1 的 `install_app` 只声明支持 IPA，本次使用 SSH + `dpkg -i` 安装 deb，再执行 sbreload。
- 安装前旧插件文件已备份到本地 `pre-upgrade-files.tar.gz`；服务恢复后 SpringBoard PID
  从 2431 变为 2782，健康接口版本和 OCR engine Schema 均确认更新。
- 本次只增加测试脚本与报告，**没有修改生产 OCR、模型、默认值、权限或版本号**；未提交、推送或发版。

```sh
printf '1\n1\n' | ./build.sh
python3 tests/paddle_package_test.py --arch arm --out PATH/package-audit.json
python3 scripts/check_paddle_binaries.py --out PATH/binary-audit.json
bash scripts/test_ocr_unit.sh
```

包：`packages/com.witchan.ios-mcp_1.2.6_iphoneos-arm.deb`，23,648,884 字节。
SHA256：`029941e71a97fc14545926bc4ac717c26657d86eabfb7af32b811b393baf5454`。
本次重新构建替换了 packages 中的上一份同名 rootful 产物；旧包已保存在本轮日志目录
`previous-rootful.deb`，之前三设备报告中的旧哈希是历史构建哈希。

ONNX Runtime 1.20.1、PP-OCRv5_mobile、OpenCV 4.10.0、Clipper 6.4.2 保持不变。
worker/ORT/OpenCV 的实际 Mach-O/归档成员为 arm64、minos=13.0；ORT 静态链接到 worker，
无独立 ORT dylib，无 Vision/CoreML/Metal 推理依赖。实际 MCP 推理返回 CPUExecutionProvider。
主 tweak、worker、两个模型与字典的安装后 SHA256 均与本次 deb 一致。
原项目的 linker、旧 libzip/helper/libcrypto 警告仍在，不代表所有非 OCR 功能均通过 iOS 13 认证。

## 验收范围与结果

仅用第三方应用页面：Cydia、同花顺、FirstApp。没有用系统设置或 Safari 页面替代。
未登录账号、交易、接受推送授权、安装 Cydia 软件包或修改应用配置。
原生 worker 的固定图片另用于算法方向测试，不冒充第三方界面或物理横屏测试。

| 功能点 | 结果 | 实际证据 |
|---|---|---|
| 新包安装及服务启动 | PASS | 新 SpringBoard PID，1.2.6 health、engine Schema 正常 |
| 旧调用不传 engine | PASS | Vision，revision 1，en-US，fast，实际识别英文 |
| 显式 engine=vision | PASS | 同样为 revision 1 英文识别 |
| Vision 英文 accurate | PASS | 显式/省略 engine 均可，CPU-only accurate 路径执行 |
| Vision 明确请求中文 | PASS | 简体/繁体/中英混合 × fast/accurate × 显式/省略 engine，12 种均返回不支持错误 |
| Paddle 中文、英文、数字 | PASS | 当前系统真实 CPU 推理，不是编译成功或引擎替身 |
| Paddle 冷/热调用 | PASS | 重复请求复用 worker PID 2803 |
| Paddle 后省略 engine | PASS | 仍为 Vision revision 1 / en-US / fast |
| 两引擎并发 | PASS | 各自返回正确引擎，不串用 |
| 非法 engine | PASS | 8 类值 × 两工具，返回 -32602 |
| 不支持语言、不回退 | PASS | 对应引擎错误，不静默换引擎 |
| describe_screen 两引擎及默认值 | PASS | OCR 分支正确；稳定后也返回 32 个 AX 元素 |
| ROI、屏外空 ROI | PASS | 正常区域文字与坐标、两引擎空区域结果正确 |
| 非法 ROI | PASS | 7 类 × 两引擎，返回 -32602 |
| 超屏 ROI | PASS | 两引擎正常裁剪并返回合法坐标 |
| JPEG 截图与逻辑点尺寸 | PASS | JPEG 实际解码，414×736；截图已人工查看 |
| Cydia OCR→ROI→tap | PASS | Paddle 两次中文 tab，Vision 两次英文 Cydia tab，4 次均命中 |
| FirstApp 宽裕 ROI 导航 | PASS | Paddle 20 点留白的 ROI，“个人中心→首页”两次命中 |
| FirstApp 很窄 ROI | FAIL（漏检） | 8 点留白返回空；整屏或 20/40 点留白可识别，未修复算法 |
| 固定图片四方向 | PASS | 真机原生 worker orientation 1/3/6/8，中文/英文/数字、已知中心与 ROI |
| CTC 阈值、空白、坏图恢复 | PASS | 真机原生 worker 实际推理 |
| 模型缺失、无回退、恢复 | PASS | Paddle 明确 missing；Vision 仍识别出 13 段文字；还原后 Paddle 正常 |
| 热会话模型损坏、无回退、恢复 | PASS | checksum mismatch；Vision 可用；原始 SHA256 恢复后 Paddle 正常 |
| Paddle 并发上限 | PASS | 第二个请求 busy、队列上限 0，同时 Vision 正常 |
| 取消与 session 隔离 | PASS | 错误 session 不误取消；正确取消后 worker PID 消失 |
| 超时 | PASS | 30.045 秒返回错误，worker PID 已消失 |
| HTTP 断连 | PASS | 对应 worker 退出，随后双引擎正常 |
| 故障后恢复 | PASS | 两引擎继续识别当前第三方页面 |
| 物理横屏 UI | SKIP | 本设备本轮未旋转第三方界面；不能用图片旋转替代 |
| iOS 13.0 / 其他 iOS 13 机型 | SKIP | 本次仅 13.5.1 / iPhone9,2，不外推所有小版本/硬件 |
| 全量 MCP、长期压力、Display Zoom | SKIP | 本轮是 OCR 兼容性专项 |

接口通用回归 `mcp_ocr_engines_test.py` 为 29 项；新增
`ocr_ios13_device_test.py` 为 37 项，全部通过。两者有部分覆盖重叠，不应当作 66 个独立功能。
`paddle_lifecycle_device_test.py` 的 7 项生命周期检查也全部通过。
资源损坏测试后再次逐文件核对安装内容，主 tweak、worker、两个模型与字典仍与 deb
SHA256 完全相等；目录中无测试备份残留。收尾再次执行 Paddle CPU 和随后默认 Vision，
均成功，AX 查询也恢复正常；health 正常，设备已返回主屏幕。
SpringBoard PID 仍为安装后的 2782，本轮测试期间未观察到额外重启。

Vision 中文错误实例如下；不是自动转成英文后输出乱码，也不是转用 Paddle：

```text
vision OCR failed: OCR languages ("zh-Hans") are not supported by Vision revision 1
on this device. Supported languages: ("en-US")
```

这台设备 `UIScreen.scale=3`、`native_scale≈2.6087`、帧缓冲 1080×1920、逻辑点 414×736。
两引擎返回坐标直接用于 tap，无额外除以 3 或 nativeScale。
Cydia 实际点击点：软件源 `(124,728)`、已安装 `(289,728)`、Cydia `(41,730)`。

## 文字与 ROI 的实际限制

| 页面/引擎 | 选定可见标签命中 | 说明 |
|---|---:|---|
| Cydia / Vision | 7/7 | 英文标签，不要求 iOS 13 Vision 识别中文 |
| Cydia / Paddle | 13/13 | 英文与中文标签 |
| 同花顺首页 / Paddle | 14/14 | 中文菜单、0%、序号与百分比数字 |
| FirstApp 首页 / Paddle | 3/3 | 首页、添加商品、个人中心 |

这是人工核对截图后的有限标签抽查，不是整页字符准确率。图标、小字、标点和形似字符
仍可能误识，不能描述为通用“100% 准确”。同花顺首次截图是应用内推送提示，
再次打开时该提示已自行消失；第一轮与旧提示文案比较的结果不计入准确率，
保留原始记录后按实际首页重新定义参考文字并重新截图、识别。

FirstApp 的“个人中心”位于底部，小字在整屏可识别，但非常窄的裁剪区域返回空数组。
留白由 8 点增至 20/40 点后同引擎识别成功；20 点留白返回的点位也实际命中导航。
失败 ROI 为 `(x=280,y=711,width=61,height=25)`；成功 ROI 为
`(268,699,85,37)` 和 `(248,679,125,57)`，均为 fixed 逻辑点。
这是本轮复现的 **Paddle ROI 漏检边界**，不因扩大 ROI 能用就记为原始用例通过。
未在本次测试中调整检测阈值、放宽校验或修改模型/预处理。

此前 223 Telegram 的超长英文行宽度上限问题也未被这次 iOS 13 验证修复，
见 [三设备报告](PADDLEOCR_TEST_RESULTS.md)。

## 测试过程中的非 OCR 断言修正

- 安装后首次 Cydia `get_ui_elements` 返回 AX inactive/timeout；后续 describe_screen
  返回 32 个元素。该初次超时保留在日志，不能声称首次 AX 查询也通过。
- Cydia 的“已安装”tab 记住了原先的包详情页面，顶部不是固定标题“已安装”，
  而是“详情”与返回“已安装”。截图确认导航已发生后修正断言，没有修改产品代码。
- FirstApp 个人页实际显示“未登录”，不是顶部标题“个人中心”；同样先查看截图再修正
  测试断言。没有点击登录、退出登录或设置。原始失败日志保留，不将错误页面预期当成坐标故障。

## 可执行测试与证据

```sh
python3 tests/mcp_ocr_engines_test.py --url http://192.168.1.17:8090/mcp --out engines.json
python3 tests/ocr_ios13_device_test.py --url http://192.168.1.17:8090/mcp --out ios13-compat.json
SSHPASS=YOUR_TEST_DEVICE_PASSWORD python3 tests/paddle_lifecycle_device_test.py \
  --url http://192.168.1.17:8090/mcp --ssh root@192.168.1.17 \
  --resources /usr/share/ios-mcp/paddleocr --app-bundle-id com.saurik.Cydia --out lifecycle.json
```

先打开 Cydia 有英文文字的首页，再执行接口测试。原生 worker 图像测试使用
`paddle_worker_test.py --worker 'SSH_COMMAND /usr/libexec/ios-mcp/mcp-ocr-worker'`
及设备的 `--resources /usr/share/ios-mcp/paddleocr --skip-resource-tests`。
该测试把固定输入传到真机执行，不在 Mac 上代跑识别；资源故障另通过 MCP 注入。

本地证据目录：`.codex-session-data/ocr-ios13.0yJIQ9/`，包括构建/安装日志、
`package-audit.json`、`binary-audit.json`、`installed-integrity.json`、`engines.json`、
`ios13-compat.json`、`native-worker.json`、`samples.json`、`taps.json`、
`firstapp-roi.json`、`lifecycle.json`、`corrupt-resource.json`、`final-state.json` 及截图。
用户应用截图不纳入公开仓库。

本次支持的结论是：当前静态链接实现已经在 **iOS 13.5.1 真机实际运行并通过上述兼容性项**；
不是对 iOS 13.0、全部机型、所有页面或原有全部 MCP 功能的无限制兼容承诺。


---

# PaddleOCR rootful 兼容性修复与回归（2026-09-25）

本页保留当时的 221 修复记录与包哈希。之后三种正式模式包已重新构建，并在
221/222/223 安装、使用第三方应用回归；最新结果及限制见
[三设备测试报告](PADDLEOCR_TEST_RESULTS.md)。下表的 222/223 SKIP 是历史状态。
后来还完成了 [iOS 13.5.1 真机补测](PADDLEOCR_TEST_RESULTS.md)；本页 iOS 13 SKIP 同样保留为历史记录。

## 问题与修复

设备：192.168.1.221，iPhone SE 第二代 / iPhone12,8 / A13，iOS 14.3，
rootful / Substitute 2.3.1。现有 Vision 可用，Paddle 原先在加载阶段失败：

```text
dyld: Library not loaded: @rpath/libonnxruntime.dylib
Reason: no suitable image found ... code signature invalid
```

worker 返回 SIGABRT（status=6），尚未进入模型推理。文件哈希与安装包相同，
不是模型不支持或推理阶段内存不足的证据。单纯重签、替换 inode、试验性增加
library-validation entitlement 均未解决真实 MCP 调用；这些试验未保留在正式构建中。
尚未确定该越狱环境底层签名策略的全部细节，不把推测当成已定位的内核缺陷。

修复：将相同 ONNX Runtime 1.20.1 CPU 构建生成的官方 combined static framework
归档链接进独立 `mcp-ocr-worker`，不再打包/加载 `libonnxruntime.dylib`。
没有修改设备安全策略、worker entitlement、模型、OCR 算法、请求默认值或 Vision 调用方式。
SpringBoard 主 dylib 仍不链接 ORT/OpenCV，Paddle 仍只用 CPUExecutionProvider。

对照验证通过 A/B/A：原动态 worker 失败 → 静态 worker 冷/热推理成功 →
终止该 worker 并恢复原动态版本后同样失败。随后正常构建并安装完整 rootful deb，
重启 SpringBoard 后再次回归，不只依赖临时替换文件的结果。

## 修改位置

- `scripts/build_paddle_runtime.sh`：iOS 取上游 `static_framework/onnxruntime.framework/onnxruntime`
  作为 `libonnxruntime.a`；macOS 测试工具的动态链接保持不变。
- `mcp-ocr-worker/Makefile`：直接链接 ORT 静态归档，移除 ORT 的动态库和 rpath 参数。
- `Makefile`、`build.sh`：依赖检查改为 `.a`，包内只放 worker 和既有模型/许可证等资源。
- `scripts/check_paddle_binaries.py`、`tests/paddle_package_test.py`：检查静态归档及实际 deb，
  拒绝再次打包 ORT dylib 或把 worker 链接回 ORT dylib。
- 测试脚本：旧 rootful 无 Python 时使用 `ps` 验证待测试 worker PID；UI 测试增加不依赖
  Frida 的 `--portrait-only`，明确不冒充横屏界面测试。

dpkg 升级后确认旧 `/usr/libexec/ios-mcp/libonnxruntime.dylib` 已按包文件归属移除。
没有自定义全盘清理或修改其他应用的文件。

## 221 实际结果

| 验证项 | 结果 | 证据/边界 |
|---|---|---|
| 完整 rootful deb 安装及服务恢复 | PASS | 新 SpringBoard PID，接口 Schema 正常 |
| 旧调用默认 Vision、显式 Vision | PASS | 识别实际屏幕文字 |
| Paddle 冷启动、热调用 | PASS | CPUExecutionProvider，重复调用同一 worker PID |
| Paddle 后省略 engine | PASS | 仍为 Vision |
| 非法 engine | PASS | 8 类值 × 两个工具，共 16 次返回 -32602 |
| `ocr_screen` ROI、两引擎空 ROI | PASS | 实际 ROI 返回框/点击点在范围内；空 ROI 返回空数组 |
| Vision/Paddle 并发 | PASS | 引擎不串用 |
| `describe_screen` 两引擎 | PASS | 正确 OCR 分支 |
| Paddle 不支持的语言 | PASS | 明确错误，不回退；随后默认 Vision 正常 |
| 上述 MCP 接口专项合计 | PASS | 29 项全部通过 |
| 中英数字原生 fixture | PASS | `中文识别测试`、`Hello OCR 12345`、`设置 Wi-Fi 8090` |
| 四个图像方向、已知框中心、ROI | PASS | 真机 native worker，方向 1/3/6/8；不等于物理 UI 旋转 |
| CTC 阈值、空白图、坏图后恢复 | PASS | 原生 worker 实际推理；会话复用 |
| 竖屏页面截图→OCR→tap | PASS | 两引擎各 3 个文字按钮 + 1 次 ROI tap，共 8 次全部命中 |
| 模型缺失、不回退及恢复 | PASS | Paddle 明确 missing；Vision 仍识别出 14 段文字；文件恢复后 Paddle 正常 |
| 队列上限及同时使用 Vision | PASS | 第二个 Paddle 返回 busy；Vision 正常 |
| 取消、不同 session 隔离 | PASS | 其他 session 不误取消；正确取消后 worker 已终止 |
| 超时 | PASS | 30.058 秒返回失败，确认 worker PID 已消失 |
| HTTP 断连 | PASS | 终止相应 worker；后续两引擎恢复 |
| 故障注入资源还原 | PASS | `rec.onnx` 存在，无测试备份残留 |
| 物理横屏 UI 点击 | SKIP | 本轮仅竖屏 UI；四方向覆盖来自原生 fixture |
| iOS 13 真机 | SKIP | **尚未完成 iOS 13 真机验证** |
| 新静态构建在 222/223 的运行 | SKIP | 此前两台通过的是动态运行库构建，不据此声称新构建通过 |
| 全部 MCP 功能、长期压力、Display Zoom | SKIP | 本轮限定 OCR 兼容性和相关路径，不是全量 46 项回归 |

这轮是兼容性回归，不是完整准确率或性能基准。不能把三行固定样本通过解释为通用准确率 100%。

## 构建与二进制检查

- rootful、roothide 正式构建模式（仍为未发布的本地 1.2.6 开发代码）均构建成功。
- worker、ORT 静态归档及两个 OpenCV 静态归档成员均为 arm64、minos=13.0。
- worker 无 ORT 动态库、Vision/CoreML/Metal/Neural Engine 链接；生产入口核验唯一可用
  EP 为 CPUExecutionProvider。SpringBoard 无 ORT/OpenCV 链接。
- 两个实际 deb 的路径、模型/字典 SHA256、许可证、worker minos/架构/链接依赖检查通过。
- 将旧动态 worker 交给新版二进制审计，能按预期拒绝，防止回归检查只会“全部通过”。
- 既有 `-multiply_defined`、arm64e deployment、libzip、旧 helper/libcrypto 等警告仍存在；
  不将此修复等同于对项目所有依赖/功能的 iOS 13 运行认证。
- 未改版本号，未执行 Git 提交、推送或发布。

| 产物 | 字节数 | SHA256 |
|---|---:|---|
| rootful deb | 23683674 | `31cd3b1c49336f4049a33ec474e03202ddea7353df633f2199638b12b6b88089` |
| roothide deb | 23622302 | `0ce532c12a272bc713cd0959264cf5fe267b19c7a03f11dae64a7acf1347021b` |
| ORT iOS 静态归档 | — | `312bd30478c3faead36d477fa6bf338836fb58b76690d586f8fa4fe9dd6c28b9` |

复现：按 [构建文档](PADDLEOCR.md) 生成运行库和所需 deb，安装后运行
`mcp_ocr_engines_test.py`、`paddle_worker_test.py`、`paddle_lifecycle_device_test.py` 和
`ocr_ui_device_test.py --portrait-only`。
本轮原始日志/JSON/截图保存在本地忽略目录 `.codex-session-data/ocr-rootful-fix.ja2uiI/`。


---

# OCR 三设备正式模式包回归（2026-09-25 至 2026-09-26）

后续补测：192.168.1.17 / iOS 13.5.1 已安装重新构建的 rootful 包，实际结果见
[iOS 13.5.1 真机报告](PADDLEOCR_TEST_RESULTS.md)。本页保留三设备当时的结果和包哈希。
packages 中同名 rootful 包之后已重新构建，旧包另存于后续日志目录 `previous-rootful.deb`。

## 结论与范围

三个 scheme 均从当前工作区重新构建正式模式 deb，并安装到对应设备。
本轮验证此前的 ORT 静态链接兼容性修复，未改动生产 OCR 算法、模型、引擎默认值或版本号。
版本仍为 `1.2.6`；这是本地正式构建模式，不表示已创建或发布 GitHub Release。
未执行 Git 暂存、提交、推送、分支或 tag 操作。

按用户追加要求，**本报告的应用页面验收只计第三方应用**。
此前已跑的系统设置/Safari 页面结果不充当本轮第三方应用结果。
执行遵循 ios-mcp-test 的先构建、安装、确认生效、再验证实际效果的流程，
覆盖范围按用户要求限定为 OCR 及相关截图、引擎路由、坐标、生命周期，不是全量 MCP 回归。

| 设备 | 实际机型与系统 | 安装包 | 第三方应用 |
|---|---|---|---|
| 192.168.1.221 | iPhone SE 第二代 / iPhone12,8 / iOS 14.3 | rootful | 抖音、iOSAutomator、Shadowrocket |
| 192.168.1.222 | iPhone 7 / iPhone9,3 / iOS 15.8.8 | roothide | 微信、Shadowrocket |
| 192.168.1.223 | iPad7,11 / iPadOS 18.3.2 | rootless | Telegram、豆包、Shadowrocket |

三台各有 29 项接口检查、31 项额外参数/资源检查、7 项生命周期检查通过，
另有每台 4 次第三方应用实际 OCR→ROI→tap 导航命中。
223 在用户手动转到横屏后，另补测两引擎共 4 次横屏 ROI 导航，全部命中。
这些通过项**不意味着任意页面识别无误**：Vision 有一处抽查文字误识，
Paddle 在 Telegram 的一条长英文 ROI 上触发了宽度限制，详见下文。

**这轮三设备测试当时尚未完成 iOS 13 真机验证**。三台系统分别为 14.3、15.8.8、18.3.2，
不能用这些结果或 minos=13.0 的编译检查替代 iOS 13 实际运行验收。

## 构建、安装和完整性

```sh
printf '1\n1\n' | ./build.sh
printf '2\n1\n' | ./build.sh
printf '3\n1\n' | ./build.sh
python3 tests/paddle_package_test.py --version 1.2.6
python3 scripts/check_paddle_binaries.py
bash scripts/test_ocr_unit.sh
```

三次构建均为 `FINALPACKAGE=1 DEBUG=0 STRIP=1`。实际 deb、模型字典校验值、
许可证、安装目录及 Mach-O 审计通过。既有的 `-multiply_defined`、arm64e deployment、
libzip 平台信息和旧 helper/libcrypto 链接警告仍存在，不宣称整个工程零警告。

依赖仍为 ONNX Runtime 1.20.1 CPU 静态库、PP-OCRv5_mobile 检测/识别模型、
OpenCV 4.10.0 core/imgproc、Clipper 6.4.2。精确来源/版本/哈希见
`third_party/paddleocr/dependencies.lock.json` 及 [构建说明](PADDLEOCR.md)。
worker 与 ORT/OpenCV archive 成员为 arm64、minos=13.0；worker 不链接 ORT 动态库、
Vision、CoreML 或 Metal。实际 Paddle 请求均返回 `CPUExecutionProvider`，
生产 worker 初始化还会核验可用 EP 列表；这不是只看 engine 名称推断 CPU。

通过 `tests/install_test_package.py` 上传/安装各自包，等待新的 SpringBoard PID
和服务恢复后才开始测试。安装后二进制、主 tweak、两个模型与字典均与 deb 对照。
221/223 对照文件 SHA256 一致；222 RootHide 会为 Mach-O 写入设备 brand 并更新签名，
所以不能直接要求整个文件哈希相等。逐字节对照仅放行已定位的 section-name 零填充区
8 字节 brand 与代码签名范围；其余内容必须完全一致，代码/数据 payload 未变化。
模型与字典仍要求完整 SHA256 相等，未放宽。

| scheme / 文件（位于 `packages/`） | 字节数 | SHA256 |
|---|---:|---|
| rootful / `com.witchan.ios-mcp_1.2.6_iphoneos-arm.deb` | 23677990 | `7a37e17049d5f3ff36d58a000479a12c74d74c73c714f2bb24aee68ee16d404d` |
| rootless / `com.witchan.ios-mcp_1.2.6_iphoneos-arm64.deb` | 23612742 | `04608b86d38744a236e905b2518b3bc415a5a0a3bbf0bc5f73a93688dd87ae8f` |
| roothide / `com.witchan.ios-mcp_1.2.6_iphoneos-arm64e.deb` | 23625122 | `21572b05cc67f47e717023bff10fc05b37f1952fd677bacd323518a78902e0a2` |

## 每台设备功能结果

以下接口、边界和故障测试的 OCR 页面均为 Shadowrocket。
PASS 包含结果断言，不只是 HTTP 请求未报错。每个原始测试 case 的请求/结果在本地 JSON 中保留。

| 功能点 | 221 | 222 | 223 | 验证内容 |
|---|---|---|---|---|
| OCR Schema | PASS | PASS | PASS | 两工具 engine 可选、枚举 vision/paddleocr |
| 不传 engine | PASS | PASS | PASS | 默认 Vision，返回实际文字 |
| 显式 vision | PASS | PASS | PASS | 仍走 Vision |
| 显式 paddleocr 冷/热调用 | PASS | PASS | PASS | CPU EP，同一 worker PID 复用 |
| Paddle 后省略 engine | PASS | PASS | PASS | 仍为 Vision，无偏好残留 |
| 非法 engine | PASS | PASS | PASS | 8 类值 × 两工具，均为 -32602 |
| 两引擎并发 | PASS | PASS | PASS | 不串引擎 |
| describe_screen 两引擎 | PASS | PASS | PASS | ocr_recognition 标识实际分支 |
| describe_screen 默认值复测 | PASS | PASS | PASS | Paddle 后省略仍为 Vision |
| Vision 英文 fast/accurate | PASS | PASS | PASS | 两级别分别执行 |
| Vision 中文+英文 accurate/fast | PASS | PASS | PASS | fast 按语言支持情况明确升 accurate |
| Paddle fast=true/false | PASS | PASS | PASS | 固定 mobile 模型，披露实际模式 |
| 两引擎不支持的语言 | PASS | PASS | PASS | 明确错误、不回退；随后默认 Vision 正常 |
| ROI 识别 | PASS | PASS | PASS | 实际文字，点位落在请求范围内 |
| 屏外空 ROI | PASS | PASS | PASS | 两引擎均为空结果 |
| 非法 ROI | PASS | PASS | PASS | 7 类输入 × 两引擎，-32602 |
| 超屏 ROI 裁剪 | PASS | PASS | PASS | 两引擎均能返回合法屏内坐标 |
| 非法置信度类型 | PASS | PASS | PASS | 字符串/数组/对象，-32602 |
| 截图 JPEG | PASS | PASS | PASS | base64 可解码显示，实际 JPEG、尺寸等于 fixed 点空间 |
| 模型缺失 | PASS | PASS | PASS | Paddle 报错、不回退；Vision 可用 |
| 模型恢复 | PASS | PASS | PASS | Paddle 恢复识别 |
| 热会话模型损坏 | PASS | PASS | PASS | checksum mismatch，不使用缓存掩盖损坏；Vision 可用 |
| 损坏测试还原 | PASS | PASS | PASS | 原始 SHA256 完全恢复，Paddle 可用 |
| Paddle 并发上限 | PASS | PASS | PASS | 第二个 Paddle busy，Vision 不被该槽位阻塞 |
| 取消与 session/ID 隔离 | PASS | PASS | PASS | 错误 session 不误取消，正确取消终止 worker |
| 30 秒超时 | PASS | PASS | PASS | 返回后检查 worker PID 已消失 |
| HTTP 断连 | PASS | PASS | PASS | 终止对应 worker，不遗留推理 |
| 故障后的双引擎恢复 | PASS | PASS | PASS | 均重新识别页面 |
| 竖屏 OCR→ROI→tap | PASS | PASS | PASS | 每引擎 app Settings→Home，共 4 次/台 |
| 横屏第三方应用 | SKIP | SKIP | PASS | 221/222 本轮未物理横屏；223 用户手动旋转后，两引擎各 2 次导航命中 |
| 全部 MCP 工具 | SKIP | SKIP | SKIP | 本次仅 OCR 专项，不是完整 46 工具回归 |
| 长期压力、Display Zoom | SKIP | SKIP | SKIP | 未在本轮覆盖 |

超时注入实际耗时：221 为 30.044 秒、222 为 30.040 秒、223 为 30.040 秒。
临时缺失/损坏模型均已恢复；这类故障为有意注入，不是正常运行发现的模型损坏。
生命周期脚本使用 `--app-bundle-id com.liguangming.Shadowrocket`，不跳到系统设置测试。
收尾再次确认三台资源目录无测试备份残留、Paddle CPU 推理成功、随后不传 engine
仍为 Vision、HTTP health 正常，并均已返回主屏幕。

竖屏点击完全使用 OCR 返回的 fixed-point `tap`，没有再除 Retina scale。
目标是 Shadowrocket 的底部导航“设置/Settings”和“首页/Home”，
通过随后页面标题、Not Connected/未连接文字和前台 bundleId 验证真实导航。
没有触碰 VPN 连接开关、发送聊天、执行付费/登录或修改账号配置。

223 手动横屏实际为 `landscape_left`：Vision 的 Settings/Home 点击点为
`(6,945)` / `(7,135)`，Paddle 为 `(7,945)` / `(7,134)`。这些仍是
`810×1080` 的 **fixed** 坐标；横屏界面映射后标签位于截图左侧，不是坐标偏移。
四次点击均验证了真实页面切换。横屏全图同时检出英文 `Not Connected`、
中文“套餐到期”和数字日期 `2026-10-18`。截图也已人工查看确认横屏内容。
本轮未覆盖反向横屏、倒置及 221/222 的第三方横屏，不能外推为所有旋转场景通过。

## 第三方页面文字抽查

方法：截图人工核对选定的可见标签，再与 OCR 文字做 NFKC、忽略空白和大小写的匹配。
这是小样本标签命中检查，**不是整页字符准确率/CER，也不是通用准确率**。
未计分文字仍可存在错误；例如图标会被识别为字符、小字/标点会变化。

| 设备 / 页面 | Vision 命中 | Paddle 命中 | ROI |
|---|---:|---:|---|
| 221 / 抖音“发现抖音朋友”页内弹层 | 6/6 | 6/6 | 两者通过 |
| 221 / iOSAutomator 英文表单 | 10/11 | 11/11 | 两者通过 |
| 221 / Shadowrocket 英文首页 | 8/8 | 8/8 | 两者通过 |
| 222 / 微信中文主页面 | 7/7 | 7/7 | 两者通过 |
| 222 / Shadowrocket 中英数字首页 | 9/9 | 9/9 | 两者通过 |
| 223 / Telegram 英文 SMS Fee 页 | 7/7 | 7/7 | Vision 通过；Paddle 长行失败，短标题通过 |
| 223 / 豆包中外文内容页 | 13/13* | 13/13* | 两者通过 |
| 223 / Shadowrocket 中英数字首页 | 9/9 | 9/9 | 两者通过 |

有效抽查标签共 70 个，Vision 命中 69 个，Paddle 命中 70 个；不要将其描述为
“Paddle 中文识别准确率 100%”。两引擎的 confidence 也未被当作等价概率比较。

*豆包原始 15 项基准中，两项不符合实际截图：手工写成“区别小说明”，实际为
“区分小说明”；动态建议“帮我写作”已不在画面，显示的是“豆包P图”。两引擎都读出了
截图上的正确文字。原始 13/15 结果未覆盖，人工复核另存 `sample-review.json`，
本表仅计算剩下 13 个有效基准，不把基准错误记成 OCR 漏识。

### 发现的限制/错误

1. **Vision 字符混淆**：221 iOSAutomator 的 `Data API URL` 被读成 `Data APl URL`
   （大写 I / 小写 l）。同页 Paddle 匹配正确。这是识别误差，不是接口或坐标故障。
2. **Paddle 长行 ROI 请求失败**：223 Telegram 整屏成功，但围住长英文说明的窄 ROI
   返回 `text line too wide (2048 normalized pixels); use a smaller region`。
   同一页面改为 `SMS Fee` 短标题 ROI，Paddle 成功且坐标在 ROI 内，无 Vision 回退。
   对应 `mcp-ocr-worker/PaddleOCR.mm` 中 `ceil(48 * line.cols / line.rows) <= 2048`
   的硬上限：ROI 改变检测框/裁剪后，细长文字行可能超过限额，导致本次请求整体失败。
   这不是 2048 点屏幕坐标上限。此次测试没有直接提高限额或改生产代码。
   如需支持该场景，应另做长行切段识别与拼接，并验证边界字符、坐标、内存和超时，
   不建议仅取消内存保护。正式对外发版前需要明确是否接受这一限制。

## 耗时观察

下表是上述真实页面的单次 MCP 端到端调用秒数，包含截图/传输/识别开销。
不是多次均值，不保证全部为同一冷/热状态，也不能跨设备不同页面直接排名。
默认参数在这些系统上因中文语言支持走 Vision accurate；不是纯英文 fast 的性能。

| 设备 / 页面 | Vision 秒 | Paddle 秒 |
|---|---:|---:|
| 221 / 抖音 | 0.709 | 2.088 |
| 221 / iOSAutomator | 0.862 | 2.072 |
| 221 / Shadowrocket | 0.685 | 2.695 |
| 222 / 微信 | 2.020 | 3.298 |
| 222 / Shadowrocket | 2.359 | 4.084 |
| 223 / Telegram | 3.214 | 3.480 |
| 223 / 豆包 | 4.195 | 3.828 |
| 223 / Shadowrocket | 3.785 | 5.998 |

## 证据及复跑

本地忽略目录：`.codex-session-data/ocr-three-release.3yfVde/`。
截图可能包含测试设备上的个人内容，因此不纳入公开文档或提交。

- `build-{1,2,3}.log`、`packages.json`、`binaries.json`：本次构建与二进制检查。
- `{221,222,223}-install.log`：安装及服务恢复。
- `installed-integrity.json`、`222-roothide-brand-audit.json`：安装内容对照。
- `{N}-thirdparty-engines.json`：29 项接口结果及耗时。
- `{N}-extra.json`：31 项额外检查结果。
- `{N}-thirdparty-lifecycle.json`：7 项故障隔离结果。
- `thirdparty/{N}-tabs.json` 及截图：每台 4 次真实 ROI 导航点击。
- `thirdparty/223-manual-landscape.json` 及截图：223 手动横屏 4 次真实 ROI 导航点击。
- `thirdparty/samples.json`、`thirdparty/sample-review.json`、各 `*-sample.jpg`：文字、ROI、实际错误与人工复核。
- `thirdparty-summary.json`：各设备核心测试组状态。
- `{N}-final-thirdparty.json`：收尾模型状态、CPU/default Vision、health 和返回主屏幕。

公共测试脚本的复跑示例（先安装匹配 scheme 的本次 deb，再打开第三方文字页面）：

```sh
python3 tests/install_test_package.py --url http://DEVICE:8090/mcp packages/MATCHING.deb
python3 tests/mcp_ocr_engines_test.py --url http://DEVICE:8090/mcp --out engines.json
SSHPASS=YOUR_TEST_DEVICE_PASSWORD python3 tests/paddle_lifecycle_device_test.py \
  --url http://DEVICE:8090/mcp --ssh root@DEVICE \
  --resources RESOLVED_JAILBREAK_ROOT/usr/share/ios-mcp/paddleocr \
  --app-bundle-id com.liguangming.Shadowrocket --out lifecycle.json
```

原始运行中遇到的启动画面、广告和系统权限弹窗不作为“第三方页面识别成功”。
微信初次地球启动画面未纳入标签结果，等待主页面后重测；不为完成测试登录或付费。
