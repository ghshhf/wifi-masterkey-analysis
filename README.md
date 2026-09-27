# WiFi万能钥匙 (com.snda.wifilocating) v5.2.20 — 隐私与逆向取证分析

> **一句话结论**：这是一款以"共享 / 破解 WiFi 密码"为核心卖点的 App，但其真实行为远不止于此——它在**明文传输 WiFi 凭证**、**后台常驻无法关闭**、**全量采集设备指纹与行为**、**内置双壳加固对抗分析**、并塞满**多家广告与推送 SDK**。本质上是一个"用你的 WiFi 密码换流量，再用你的隐私换钱"的采集器。

---

## 0. 声明 / Disclaimer

- 本仓库是对作者**自行持有**的一款商业安装包（`WiFi万能钥匙_5.2.20.apk`）的**防御性安全研究与消费者隐私剖析**。
- 分析**仅限静态逆向**（清单解析、DEX 字符串提取、native 库扫描、网络端点归类），**未执行 APK、未重打包、未解密任何加固资源**。
- **本仓库不传播 APK 二进制，不提供针对任意第三方网络的攻击方法**；所有结论均来自安装包自身留下的字符串与组件证据。
- 如发现错漏，欢迎 Issue / PR 指正。旨在提升公众对"免费 WiFi 工具"隐私代价的认知。

---

## 1. 基本信息

| 项 | 值 |
|---|---|
| 包名 | `com.snda.wifilocating`（盛大） |
| 版本 | 5.2.20（VersionName），minSdk 22 / targetSdk 30 |
| 体积 | 84,404,087 字节（≈80.5 MB） |
| APK 条目 | 7,625 |
| DEX | 10 个（classes.dex … classes10.dex），约 **58 万字符串** |
| 原生库 | **159 个** `.so`（arm64-v8a × 84 + armeabi-v7a × 75） |
| 组件（解码后清单） | Activity 66 / Service 129 / Receiver 36 / Provider 17（导出 34/114/22/7） |
| 权限 | **62 项**（高危/敏感 23 项） |
| 加固 | 爱加密 `libijiami_ijm.so` + 顶象 `libDXRisk` **双壳** |

> ⚠️ 注意包名同时出现 `com.snda.wifilocating`（盛大原始）、`com.wifitutu.*`（疑似换皮/子品牌 "WiFi兔子"）、`com.lantern.*`（守护进程命名空间）、`com.halo.wifikey.*`——典型的**收购 / 白标 / 多包名共存**痕迹。

---

## 2. 它到底是什么：WiFi 密码的"云端共享"模型

"**获取你的密码 → 上传云端 → 别人可查**"——这一核心机制被 DEX 字符串直接坐实：

- 配置类：`com/wifitutu/link/wifi/config/api/generate/wifi/WiFiPwdShareConfig`（WiFi 密码**共享配置**）
- 取密接口（同步）：
  - `com/wifitutu/link/feature/wifi/FeatureWifi$getWifiPasswdsSync`
  - `com/wifitutu/link/feature/wifi/FeatureWifi$getPengWifiPasswdSync`
- 查询事件：`BdConnectQueryPwdEvent` / `BdConnectQueryPwdSuccessEvent` / `BdConnectQueryPwdFailEvent`
- 结果类：`WifiPasswdResult`、`WIFI_QR_REQUEST_PASSWD`
- **明文**凭证查询/鉴权端点（直接在 DEX 中硬编码）：
  - `http://%s:9999/api/devices/get_freewifiinfo_by_ip`
  - `http://%s:9999/auth/alps/fa.ss`
  - `http://cc.freewifi.com:9999/api/devices/get_freewifiinfo_by_ip`
  - `http://alps.51y5.net/alps/sco/checknet.do`
  - `http://ap-alps-tt.ieeewifi.com/alps/fa.ss`

**机制推断**（基于字符串，非运行时验证）：
1. 你连接某个 WiFi 时，App 把 `SSID / BSSID / 密码 / 设备 IMEI` 上传到云端共享库（"共享"）。
2. 别人遇到同一热点时，App 用 `getWifiPasswdsSync` / `BdConnectQueryPwd*` 向 `:9999` 接口查询，返回该热点的共享密码并尝试连接。
3. 设备绑定证据：`IMEI is duplicated reported by server. Give up now.`、`Invalid Imei, Register again.`、`JIGUANG-JDeviceImeiHelper`——**用 IMEI 把共享行为绑定到设备**。

> 关键风险：第 1 步意味着**你自家路由器的密码，会被明文上报给厂商云端**。第 2 步意味着任何能查到该热点的人都能拿到密码——这是该品类 App 长期被诟病的核心隐私问题。

---

## 3. 权限面：62 项，23 项高危

完整清单见 [`evidence/permissions.md`](evidence/permissions.md)。最刺眼的 23 项高危权限：

| 权限 | 它能拿到什么 |
|---|---|
| `READ_PRIVILEGED_PHONE_STATE` | **IMEI / IMSI / 设备唯一标识**（普通 App 拿不到，需系统级） |
| `PACKAGE_USAGE_STATS` | 你**用了哪些 App、用了多久** |
| `QUERY_ALL_PACKAGES` | **全盘 App 列表** |
| `ACCESS_FINE / COARSE_LOCATION` | 精确 / 粗略地理位置 |
| `CAMERA` / `RECORD_AUDIO` | 摄像头 / 麦克风 |
| `READ / WRITE_EXTERNAL_STORAGE` + `READ_MEDIA_IMAGES` | 外部存储 / 相册 |
| `SYSTEM_ALERT_WINDOW` | 全局悬浮窗（可盖在别的 App 上） |
| `REQUEST_INSTALL_PACKAGES` | **静默/诱导安装其他 APK** |
| `NFC` / `BLUETOOTH_*` | 近场通信 / 蓝牙 |
| `GET_TASKS` / `REORDER_TASKS` | 当前运行任务栈 |
| `READ_APP_BADGE` + 各厂商 `launcher` 设置 | 桌面角标/快捷方式操控 |

> `READ_PRIVILEGED_PHONE_STATE` 是系统签名级权限——普通上架应用不应拥有。它的存在说明该 App 通过厂商预装 / 特殊渠道获取了超出常规的能力。

---

## 4. 关不掉的幽灵：后台常驻体系

解码清单暴露出一套**多层保活**架构，目的就是"即使你关掉 App，它也在跑"：

- **双进程守护**：`com.lantern.daemon.doubleprocess.PersistentReceiver` 监听 `QUICKBOOT_POWERON`（关机再开机也能拉起）、`ACTION_NEW_PICTURE`、`ACTION_NEW_VIDEO`、`BADGE_COUNT_UPDATE`——只要系统有任意事件就复活。
- **前台服务保活**：`com.lantern.daemon.notification.ForegroundServiceHelper$InnerService`——借前台服务（常驻通知）绕过后台限制。
- **JobScheduler 周期任务**：`com.lantern.daemon.JobSchedulerService`、`com.wifitutu.katool.job.JobSchedulerService`——即便被杀，系统也会周期性重启它。
- **借 Android 账号框架持久化**：`com.lantern.daemon.farmore.account.AccountAuthenticatorService` + `AccountSyncService` / `AccountSyncV5Service` / `AccountAuthenticatorV5Service`——注册一个"假系统账号"并通过系统 Sync 机制同步数据（共享凭证 / 用户画像），**比 App 本身更难彻底清除**。
- **多厂商推送互相拉活**：极光 JPush（`JPushDaenomService`）、个推（`TutuPushService`）、华为 HMS、小米 XMPush、OPPO、vivo、荣耀——任一通道收到推送都会把 App 唤醒，形成"谁都杀不死"的唤醒网。
- **WorkManager 自调度**：`androidx.work.impl.background.systemalarm.RescheduleReceiver` 监听 `BOOT_COMPLETED` 自重启周期任务。

> 大量"手机管家"式壳功能（`QuickSettings*Service` 共数十个：清理/加速/省电/安全/内存/流量/降温/碎片整理）不只是凑数——它们是**留在桌面、合理化权限申请、制造"有用"错觉**的载体。

---

## 5. 设备指纹与隐私采集

- **设备指纹全家桶**：
  - 顶象 `libDXRisk-v7_7_1r_*.so` + `libDXRiskComm`（风控/设备指纹，native 字符串含 `https://constid.dingxiang-inc.com/udid/m1`、`/udid/sa-m`——直接回传设备 ID）
  - `libwdid_clean_new.so`（设备 ID 生成）、`libphonemark.so`（设备标记）、`libadinfo.so`（广告信息）、`libmetis.so`、`libturingau.so`
  - MOB：`api.verify.mob.com` / `cache.verify.mob.com` / `cdn-api-verify.mob.com`
- **实名 / 手机号链路**：`libCtaApiLib.so` 内含 `cn/com/chinatelecom/account/api/encrypt/SHA_256`（电信账号加密）+ `https://id6.me/gw/presdk.do`（**短信验证码 SDK**）——表明它集成了手机号/电信账号相关的实名或验证能力。
- **定位 SDK**：百度 `liblocSDK8b.so` + `libindoor.so` + `libmaparmor.so`（室内/地图定位）。
- **IMEI/IMSI 直采**：`getDeviceId`、`JDeviceSimInfo{imei=`、`IMSICollectionSwitch`、以及第 2 节所述"IMEI 重复上报"逻辑。

---

## 6. 明文传输与数据外泄

- **180 条 `http://` 明文 URL**（vs 730 条 https）。其中包括：
  - 上文 `:9999` 的 **WiFi 凭证查询 / 鉴权接口明文**——**中间人可截获被共享的 WiFi 密码**。
  - `http://5693cc1342ef49b493f3fe7afa7cd3ae@192.168.2.23:9000/2`——**Sentry DSN 泄露了厂商内网 IP `192.168.2.23`**（开发/测试环境暴露）。
  - `http://192.168.2.21:8080`、`http://10.38.162.35:9085` 等内网地址残留。
  - 多个 `adx.ad.pre.wkanx.com`、`t1.wkanx.com`、`adx-ad-prod.wkanx.com` 明文广告配置端点。
- Sentry 上报域名 `sentry.ttwifi.net`（多个 project key）。
- 私有 DoH：`dns.alidns.com` / `doh.pub`——App 自带 DNS 解析，可能用于绕过网络层面的审查/过滤。

---

## 7. 广告与变现 SDK 全家桶

| SDK | 证据 |
|---|---|
| **腾讯广点通（GDT）** | `libyaqcore_gdtadv.so` / `libyaqstub_gdtadv.so`；`sdk.e.qq.com`、`qzs.gdtimg.com`、`v.gdt.qq.com`、`mi.gdt.qq.com`、`c.gdt.qq.com/gdt_trace_a.fcg`、`union.eff.qq.com` |
| **字节 Pangle** | `libpanglearmor.so` / `libpangleflipped.so`；`openadsdk.permission.TT_PANGOLIN`；`sf3-fe-tos.pglstatp-toutiao.com`、`com.byted.live` |
| **极光 JPush** | `JPushDaenomService`、`JIGUANG-JDeviceImeiHelper`、`com.snda.wifilocating.permission.JPUSH_MESSAGE` |
| **个推** | `getui.permission.GetuiService`、`TutuPushService` |
| **厂商推送** | 华为 HMS / 小米 XMPush / OPPO / vivo / 荣耀 HonorPush |
| **支付宝** | `mclient.alipay.com`、`wappaygw.alipay.com`（支付/变现） |

> 一个"WiFi 工具"同时内置腾讯、字节、极光、个推、厂商推送五路广告/推送 SDK，且**互相拉活**——变现意图压倒工具属性。

---

## 8. 能力越界与臃肿

- **React Native 巨无霸栈**：`libhermes.so`、`libreanimated.so`、`libyoga.so`、`libfbjni.so` 等数十个 RN 运行时库——整套 UI 用 RN 重写，体积与攻击面巨大。
- **腾讯云实时语音识别 `libqcloud_asr_realtime.so`**：一个 WiFi App 要语音识别干嘛？能力明显越界，疑似为"语音助手 / 语音搜索"或埋点交互预留。
- **摄像头 `libVisionCamera.so` + `CAMERA` 权限**：疑似扫码连 WiFi，但也可被滥用于更隐蔽的采集。
- **小程序容器 FinClip**：`libfinmp3lame.so`、`fin_applet_*`——内置小程序运行时，进一步膨胀并增加未知第三方代码执行面。
- **CoinSdk 任务 SDK**：`com.zenmen.coinsdk`（"福利/金币"任务体系，典型诱导留存 + 广告变现）。

---

## 9. 加固与反逆向

- **双壳**：爱加密 `libijiami_ijm.so` + `libijm_linker.so` **和** 顶象 `libDXRisk-v7_7_1r*.so`——DEX 被保护，直接 jadx 只能看到壳外代码。
- **反调试 / 反 Root / 反 Frida / 反 Xposed**：
  - `debuggable release cert app rejected`、`check safe f: debuggable`
  - `com.thirdparty.superuser`、`/system/app/Superuser.apk`、`com.koushikdutta.superuser`
  - `frida` / `xposed` 检测串
- **VPN Service**：`Landroid/net/VpnService`、`com.sansecy.echo.base.BaseVpnService`——内置 VPN 能力（可能用于流量转发 / 加速 / 代理，需警惕流量被接管）。
- **热修复 / 动态更新**：`libpatch.so`（hot-patch），可在不更新 App 的情况下远程改逻辑——**运行时行为不可控**。

---

## 10. 结论：它有多"恶心"（量化）

| 维度 | 表现 | 风险等级 |
|---|---|---|
| WiFi 密码共享 | 明文上传自家密码到云端，别人可查 | 🔴 极高 |
| 后台常驻 | 双进程 + 前台服务 + JobScheduler + 账号同步 + 多推送互拉，**无法彻底关闭** | 🔴 极高 |
| 隐私采集 | IMEI/IMSI（系统级权限）、用 App 列表、定位、摄像头、麦克风、NFC | 🔴 极高 |
| 明文传输 | 180 条 http，含 WiFi 凭证接口与内网 IP 泄露 | 🔴 高 |
| 设备指纹 | 顶象 + wdid + phonemark + MOB + 电信实名 | 🔴 高 |
| 广告变现 | 腾讯/字节/极光/个推/厂商推送 五路 + 互相拉活 | 🟠 中 |
| 能力越界 | RN 巨栈 + 语音识别 + 小程序 + 金币任务 | 🟠 中 |
| 加固对抗 | 双壳 + 反调试/反 Frida + VPN + 热修复 | 🟠 中（阻碍审计） |

**总评**：这是一款**隐私代价远高于工具价值**的 App。它的"免费连 WiFi"是用**你家的路由器密码 + 你的全量设备画像**换来的，且通过多层保活确保"进了门就赶不走"。**强烈建议不安装；已安装者卸载并修改自家 WiFi 密码。**

---

## 11. 给普通用户的建议

1. **卸载**该 App，并**修改你家路由器的 WiFi 密码**（因为你连接过的密码可能已被上传）。
2. 在系统"设置 → 账号"里**删除其注册的系统账号**（`com.lantern.daemon.farmore...` 类账号），否则 Sync 会残留。
3. 用系统自带 WiFi 或可信来源，避免任何"共享密码"类工具。
4. 定期检查"自启动 / 后台活动 / 特殊权限"，收回不必要授权。

---

## 12. 方法论与复现

工具链（本机已具备）：Java 21（`/e/jdk21`）、apktool、frida 环境、adb。

步骤：
1. **清单解码**：`java -jar apktool.jar d -f -o wifi_apktool_out <apk>` → 得到解码后的 `AndroidManifest.xml` 与 `smali_classes1..10`。
2. **DEX 字符串提取**：见 [`analysis/apk_reverse.py`](analysis/apk_reverse.py)——解析清单、抽取 58 万字符串、归类 URL/域名/IP/安全关键字。
3. **深度取证**：见 [`analysis/wifi_deep_analysis.py`](analysis/wifi_deep_analysis.py)——从解码清单抽取权限/组件/意图过滤器，扫 smali 关键词。
4. **native 库取证**：见 [`analysis/so_strings.py`](analysis/so_strings.py)——从关键 `.so` 抽取可打印字符串与 URL。
5. **（未做）动态分析**：需 Android 设备/模拟器 + Frida 脱壳（顶象/爱加密）+ 运行时 hook `getWifiPasswdsSync` 抓包，才能看清壳内真实逻辑与加密方式。

> 注：jadx 在本环境因网络限制未能下载，故主要依赖 apktool(smali) + 字符串分析。双壳保护下伪 Java 可读性有限，结论以"App 自身留下的字符串与组件"为准。

---

## 13. 合规与边界

- 本仓库**仅含分析方法论、本人持有的安装包之静态证据摘录（类名/域名/接口片段）与结论**，**不含 APK 二进制、不含任何反编译出的专有源代码全文**。
- 研究目的为**消费者隐私警示与防御性安全认知提升**，不提供针对第三方网络的攻击能力。
- 商标与代码版权归原作者所有；如权利人认为本仓库内容不当，请联系删除。

---

## 文件结构

```
.
├── README.md                      # 本文
├── LICENSE                        # MIT
├── .gitignore
├── evidence/
│   ├── permissions.md             # 完整 62 项权限清单
│   ├── native_libs.md             # 159 个 native 库归类
│   └── network_endpoints.md       # 网络端点归类（后端/广告/指纹/明文）
└── analysis/
    ├── apk_reverse.py             # 清单+DEX字符串静态拆解
    ├── wifi_deep_analysis.py      # 深度取证（权限/组件/关键词）
    └── so_strings.py              # native 库字符串取证
```
