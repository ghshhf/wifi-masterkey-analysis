#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WiFi万能钥匙 5.2.20 深度取证：从 apktool 解码产物 + APK 提取证据，结构化输出。"""
import os, re, json, glob, collections

APKTOOL = r"E:/xmanbian/_tools/wifi_apktool_out"
APK = r"E:/Users/123/Desktop/1/Telegram Desktop/WiFi万能钥匙_5.2.20.apk"
OUT = r"E:/xmanbian/tools_and_notes/wifi_evidence.md"

# ---------- 1. 权限 ----------
perm_re = re.compile(r'android:name="(android\.permission\.[A-Z_]+)"')
prot_re = re.compile(r'android:protectionLevel="([^"]+)"')
manifest = open(os.path.join(APKTOOL, "AndroidManifest.xml"), encoding="utf-8", errors="ignore").read()
# 逐段切分 <uses-permission .../>
perms = re.findall(r'<uses-permission\b[^>]*?android:name="([^"]+)"[^>]*?/?>', manifest)
# 含 protectionLevel 的
perm_blocks = re.findall(r'<uses-permission\b[^>]*?/>', manifest)
perm_info = []
for b in perm_blocks:
    name = re.search(r'android:name="([^"]+)"', b)
    prot = re.search(r'android:protectionLevel="([^"]+)"', b)
    if name:
        perm_info.append((name.group(1), prot.group(1) if prot else "normal/dangerous(default)"))

# ---------- 2. 组件 + 意图过滤器 ----------
def comp_section(tag):
    return re.findall(r'<%s\b.*?</%s>' % (tag, tag), manifest, re.S)

comp_data = {}
for tag in ["activity", "service", "receiver", "provider"]:
    secs = comp_section(tag)
    items = []
    for s in secs:
        nm = re.search(r'android:name="([^"]+)"', s)
        if not nm: 
            continue
        name = nm.group(1)
        exported = re.search(r'android:exported="([^"]+)"', s)
        perms_c = re.search(r'android:permission="([^"]+)"', s)
        intents = re.findall(r'<intent-filter\b.*?</intent-filter>', s, re.S)
        actions = []
        for it in intents:
            actions += re.findall(r'<action\b[^>]*?android:name="([^"]+)"', it)
        items.append({
            "name": name,
            "exported": exported.group(1) if exported else "?",
            "permission": perms_c.group(1) if perms_c else "",
            "actions": actions,
        })
    comp_data[tag] = items

# 关键意图：自启动 / 监听安装 / 网络变化
KEY_INTENTS = ["BOOT_COMPLETED", "PACKAGE_ADDED", "PACKAGE_REPLACED", "CONNECTIVITY_CHANGE",
               "USER_PRESENT", "SCREEN_ON", "SCREEN_OFF", "MY_PACKAGE_REPLACED", "QUICKBOOT_POWERON"]
boot_receivers = []
for r in comp_data["receiver"]:
    for a in r["actions"]:
        if any(k in a for k in KEY_INTENTS):
            boot_receivers.append((r["name"], a))
            break

# ---------- 3. smali 扫描 ----------
EVID = {
    "wifi_share": ["getWifiPasswdsSync","getPengWifiPasswdSync","BdConnectQueryPwd","WiFiPwdShare","freewifi",
                   "wifipwd","WifiPwd","shareWifi","uploadWifi","queryWifi","get_freewifi","connectWifi",
                   "9999/api","getPasswd","WifiPassword","pwdShare","cloudWifi","getWifiKey","wifikey"],
    "privacy_exfil": ["getDeviceId","getSubscriberId","getIMEI","getIMSI","READ_PRIVILEGED_PHONE_STATE",
                      "getLastKnownLocation","getLatitude","getLongitude","readContacts","getInstalledPackages",
                      "PACKAGE_USAGE_STATS","getMacAddress","getSimSerial","getLine1Number","SerialNumber",
                      "Build.SERIAL","settings.Secure.ANDROID_ID","getAccounts"],
    "plaintext_http": [r'http://'],
    "crypto": ["AES","DES","RSA","encrypt","decrypt","Cipher","SecretKey","IvParameterSpec","MD5","SHA1","base64"],
    "antire": ["frida","xposed","substrate","SUPERUSER","Superuser","debuggable","root","hook","anti"," tamper",
               "libDXRisk","libijiami","ijm","DXRisk","trace","ptrace","dump"],
    "ad_sdk": ["gdt","GDT","qq.com","alipay","umeng","mob","dingxiang","id6.me","adunion","adx","sdk.e.qq.com",
               "qzs.gdtimg","v.gdt.qq","pangle","csj","byted","byte_dance","reward"],
    "vpn": ["VpnService","BaseVpnService","establish","Vpn","tun2socks","tunnel"],
}
smali_dirs = [APKTOOL] + [os.path.join(APKTOOL, d) for d in os.listdir(APKTOOL) if d.startswith("smali")]
smali_files = []
for d in smali_dirs:
    smali_files += glob.glob(os.path.join(d, "**", "*.smali"), recursive=True)
print(f"[*] smali 文件数: {len(smali_files)}")

# 为避免超大文件拖慢，用 grep 式逐文件扫描
hits = {k: collections.Counter() for k in EVID}
total_lines = 0
file_with_http = set()
for f in smali_files:
    try:
        with open(f, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                total_lines += 1
                ll = line
                for cat, pats in EVID.items():
                    for p in pats:
                        if re.search(p if p.startswith(r'\b') or '\\' in p else re.escape(p), ll, re.I):
                            hits[cat][p] += 1
                            if cat == "plaintext_http":
                                file_with_http.add(f)
    except Exception as e:
        pass

# ---------- 4. native 库 ----------
libs = []
libdir = os.path.join(APKTOOL, "lib")
if os.path.isdir(libdir):
    for root, _, files in os.walk(libdir):
        for fn in files:
            if fn.endswith(".so"):
                fp = os.path.join(root, fn)
                arch = os.path.basename(os.path.dirname(fp))
                libs.append((arch, fn, os.path.getsize(fp)))
libs.sort()

# ---------- 5. 输出 ----------
with open(OUT, "w", encoding="utf-8") as o:
    o.write("# WiFi万能钥匙 5.2.20 取证证据 (apktool + smali + native)\n\n")
    o.write(f"- APK: {APK}\n- 解码目录: {APKTOOL}\n- smali 文件: {len(smali_files)}, 扫描代码行: {total_lines}\n\n")
    o.write("## 1. 权限清单 ({n})\n".format(n=len(perm_info)))
    # 危险权限高亮
    danger_kw = ["LOCATION","CAMERA","MICROPHONE","PHONE","SMS","CONTACTS","STORAGE","READ_","WRITE_",
                 "PACKAGE_USAGE","QUERY_ALL","SYSTEM_ALERT","REQUEST_INSTALL","NFC","BLUETOOTH","GET_TASKS"]
    o.write("| 权限 | 保护级别 | 敏感 |\n|---|---|---|\n")
    for name, prot in perm_info:
        sens = "🔴" if any(k in name for k in danger_kw) else ""
        o.write(f"| `{name}` | {prot} | {sens} |\n")
    o.write("\n## 2. 四大组件\n")
    for tag in ["activity","service","receiver","provider"]:
        o.write(f"- {tag}: {len(comp_data[tag])}\n")
    o.write("\n### 2.1 自启动/系统事件监听 Receiver ({len(boot_receivers)})\n")
    for nm, act in boot_receivers:
        o.write(f"- `{nm}` ← `{act}`\n")
    o.write("\n### 2.2 导出组件 (exported=true, 潜在攻击面)\n")
    for tag in ["activity","service","receiver","provider"]:
        exp = [c for c in comp_data[tag] if c["exported"]=="true"]
        o.write(f"- {tag} exported=true: {len(exp)}\n")
        for c in exp[:15]:
            o.write(f"  - `{c['name']}`{(' perm='+c['permission']) if c['permission'] else ''}\n")
        if len(exp)>15: o.write(f"  - ...(共{len(exp)})\n")
    o.write("\n## 3. smali 关键词命中 (按类别)\n")
    for cat, ctr in hits.items():
        o.write(f"\n### {cat} (不同模式命中 {sum(ctr.values())} 次, 模式数 {len(ctr)})\n")
        for pat, n in ctr.most_common(25):
            o.write(f"- `{pat}` × {n}\n")
    o.write(f"\n> 含明文 http:// 的 smali 文件数: {len(file_with_http)}\n")
    o.write("\n## 4. native 库 ({n})\n".format(n=len(libs)))
    o.write("| arch | 名称 | 大小 |\n|---|---|---|\n")
    for arch, fn, sz in libs:
        o.write(f"| {arch} | `{fn}` | {sz//1024} KB |\n")
print(f"[*] 证据已写入 {OUT}")
print(f"[*] 权限 {len(perm_info)} | receiver自启动 {len(boot_receivers)} | http文件 {len(file_with_http)} | libs {len(libs)}")
