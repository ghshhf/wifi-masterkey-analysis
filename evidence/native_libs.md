# Native 库取证（159 个 .so）

> 来源：`apktool` 解码产物 `lib/` 目录（arm64-v8a × 84 + armeabi-v7a × 75）。
> 双架构同名库不重复列举，以下按**功能归类**列出关键库及其含义；每个库在两种架构下均存在。

## 1. 加固 / 风控 / 反逆向（最危险）

| 库 | 身份 | 含义 |
|---|---|---|
| `libijiami_ijm.so` + `libijm_linker.so` | **爱加密** | App 加壳/防篡改/防 dump 主壳 |
| `libDXRisk-v7_7_1r_f9c632ad.so` + `libDXRiskComm-v7_7_1r_f9c632ad.so` | **顶象** | 设备指纹 + 风控 + 反作弊 |
| `libphantom.so` | 疑似反模拟器/反调试 | 模拟器/调试检测 |
| `libmetis.so` | 数据/追踪 | 数据采集 SDK |
| `libpatch.so` | 热修复 | 远程改逻辑 |
| `libkey.so` | 密钥/加解密 | 本地密钥管理 |

## 2. 后台常驻守护（"关不掉"的核心）

| 库 | 含义 |
|---|---|
| `libcore_daemon_new.so` / `libcoreManger_new.so` / `libcxCoreManger.so` | 核心常驻守护进程 |
| `libdaemon_api20.so` / `libdaemon_api21.so` | 按 Android API 级别的守护实现（`DAEMON`/`Daemon` 常量） |
| `libflare.so` | 疑似保活/网络 |

## 3. 设备指纹 / 隐私采集

| 库 | 含义 |
|---|---|
| `libwdid_clean_new.so` | 设备 ID 生成（wdid） |
| `libphonemark.so` | 设备标记（phone mark） |
| `libadinfo.so` | 广告信息收集 |
| `libidatools.so` | 数据工具 |
| `libturingau.so` | 反机器人/风控 AU |
| `libCtaApiLib.so` | 电信账号 SHA256 加密 + `id6.me` 短信 SDK |
| `libtobEmbedEncrypt.so` | 头条系嵌入加密 |

## 4. 广告 / 推送 SDK

| 库 | 身份 |
|---|---|
| `libyaqcore_gdtadv.so` / `libyaqstub_gdtadv.so` | **腾讯广点通 GDT** |
| `libpanglearmor.so` / `libpangleflipped.so` | **字节 Pangle** |
| `liboctopus.so` / `libods.so` | 广告/数据（未知具体） |

## 5. 定位 / 地图

| 库 | 身份 |
|---|---|
| `liblocSDK8b.so` | 百度定位 SDK |
| `libindoor.so` | 室内定位 |
| `libmaparmor.so` | 地图 SDK 防护 |

## 6. 能力与越界

| 库 | 含义 |
|---|---|
| `libqcloud_asr_realtime.so` | **腾讯云实时语音识别**（WiFi App 要语音？） |
| `libVisionCamera.so` | 摄像头（RN 相机） |
| `libfinmp3lame.so` | FinClip 小程序容器（MP3 编解码） |
| `libreanimated.so` / `libhermes.so` / `libyoga.so` / `libfbjni.so` / `libfolly_runtime.so` / `libglog.so` | **React Native 巨栈** |
| `libsentry.so` / `libsentry-android.so` | Sentry 上报（泄露内网 DSN 见主报告 §6） |
| `libmmkv.so` | 腾讯 MMKV 本地存储 |
| `libqcloud_asr_realtime.so` | 腾讯云 ASR |

## 7. 其他基础设施

`libc++_shared.so`、`libglide-webp.so`、`libgifimage.so`、`libimagepipeline.so`、`libjsi.so`、
`libjsinspector.so`、`libturbomodulejsijni.so`、`libreactnativejni.so`、`libuimanagerjni.so`、
`libwebgl.so`、`liblogger.so`、`libmetis.so`、`liboctopus.so`、`libods.so`、`liblink-empty.so`、
`liblink-foundation.so` 等（React Native / 图片 / 日志 / 链接 基础设施）。

> 注：加固库（§1）与守护库（§2）多为 **stripped**，可直接读出的字符串极少（如 `libCtaApiLib.so` 仅泄露 `id6.me/gw/presdk.do` 与电信 SHA256 接口），印证了反分析意图。
