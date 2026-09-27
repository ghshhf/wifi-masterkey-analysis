# 网络端点归类

> 来源：DEX 字符串（58 万）+ native 库字符串。共提取 URL 910 条（去重），其中 **明文 `http://` 180 条** / `https://` 730 条；域名 826 个；IP 60 个。
> 下列为**按功能归类的关键端点**；完整 910 条不在本仓库分发（属静态提取产物，可按 `analysis/` 脚本复现）。

## 1. WiFi 凭证共享 / 鉴权（明文 http ⚠️）

- `http://%s:9999/api/devices/get_freewifiinfo_by_ip`
- `http://%s:9999/auth/alps/fa.ss`
- `http://cc.freewifi.com:9999/api/devices/get_freewifiinfo_by_ip`
- `http://alps.51y5.net/alps/sco/checknet.do`
- `http://ap-alps-tt.ieeewifi.com/alps/fa.ss`

> 这些接口用于"查询/上传 WiFi 热点密码"，**走明文 http**，存在中间人截获风险（详见主报告 §2、§6）。

## 2. 自有后端（51y5.net / wkanx / ttwifi）

- `img03.51y5.net`、`filex.51y5.net`、`dcmdaa.51y5.net`、`check02.51y5.net`、`wifi3a.51y5.net`
- `adx.ad.pre.wkanx.com`、`t1.wkanx.com`、`adx-ad-prod.wkanx.com`（广告）
- `sentry.ttwifi.net`（Sentry 上报，多个 project key）

## 3. 广告 SDK

**腾讯广点通 GDT**
- `sdk.e.qq.com`、`qzs.gdtimg.com`、`v.gdt.qq.com`、`mi.gdt.qq.com`
- `c.gdt.qq.com/gdt_trace_a.fcg`、`union.eff.qq.com/pantheon/c/v1/log/app/report`

**字节 Pangle / 字节系**
- `sf3-fe-tos.pglstatp-toutiao.com`、`com.byted.live`
- `openadsdk.permission.TT_PANGOLIN`

## 4. 设备指纹 / 验证

- `https://constid.dingxiang-inc.com/udid/m1`、`/udid/sa-m`（顶象设备指纹）
- `api.verify.mob.com`、`cache.verify.mob.com`、`cdn-api-verify.mob.com`（MOB）
- `https://id6.me/gw/presdk.do`（短信验证码 SDK，native `libCtaApiLib.so` 中硬编码）
- `cn/com/chinatelecom/account/api/encrypt/SHA_256`（电信账号加密，native）

## 5. 定位 / 地图

- `api.map.baidu.com`、`loc.map.baidu.com`（百度地图/定位）

## 6. 支付

- `mclient.alipay.com`、`wappaygw.alipay.com`、`com.alipay.android.app`

## 7. 推送（多厂商，互相拉活）

- 极光 JPush：`JIGUANG-JDeviceImeiHelper`、极光 AppKey
- 个推 Getui：`getui.permission.GetuiService`
- 华为 HMS / 小米 XMPush / OPPO / vivo / 荣耀 HonorPush

## 8. 私有 DNS（DoH）

- `https://dns.alidns.com/dns-query`、`https://doh.pub/dns-query`

## 9. 明文 / 内网泄露（🔴）

- `http://5693cc1342ef49b493f3fe7afa7cd3ae@192.168.2.23:9000/2` —— **Sentry DSN 泄露厂商内网 IP `192.168.2.23`**
- `http://192.168.2.21:8080`
- `http://10.38.162.35:9085`
- `http://a.app.qq.com/o/simple.jsp?pkgname=com.snda.wifilocating&ckey=CK7257340277627561984`（应用宝分发）

> 结论：该 App 的"共享 WiFi 密码"走明文 http，且开发/测试环境内网地址残留于正式包，安全实践严重不足。
