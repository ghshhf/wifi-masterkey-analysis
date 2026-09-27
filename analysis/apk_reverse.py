#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
静态逆向拆解脚本（仅静态分析，不执行、不重打包）。
目标：WiFi万能钥匙_5.2.20.apk
产出：manifest 解析 + DEX 字符串提取（URL/域名/关键字）+ native .so 扫描（含加壳特征）。
"""
import zipfile, struct, re, os, sys
from collections import Counter

APK = r"E:/Users/123/Desktop/1/Telegram Desktop/WiFi万能钥匙_5.2.20.apk"
TMP = r"E:/xmanbian/_tmp/apk_wifi_tmp"
OUT = r"E:/xmanbian/tools_and_notes/wifi_masterkey_5.2.20_reverse.md"
os.makedirs(TMP, exist_ok=True)

URL_RE   = re.compile(rb'https?://[^\s"\'<>{}|\^`\\]+', re.I)
HOST_RE  = re.compile(rb'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|cn|net|org|io|me|tv|co|info|biz|xyz|top|cc|vip|club|live|tech|app|pro|fun|work|cloud|us|uk|ru|jp|kr|hk|tw|de|fr|in|br|ca|au|gov|edu|mobi|name|ws|nu|sh|so|la|pw|ga|cf|gq|ml|tk|gg|to|im|is|ai|dev|store|online|site|space|website)\b', re.I)
IP_RE    = re.compile(rb'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{1,5})?\b')
KW_RE    = re.compile(rb'(password|passwd|pwd|wifipwd|wifikey|ssid|psk|token|secret|api[_-]?key|app[_-]?key|access[_-]?key|client[_-]?secret|aes|rsa|des|3des|encrypt|decrypt|md5|sha1|sha256|base64|sign|salt|\\biv\\b|cipher|ssl|tls|x509|certificate|\.p12|\.bks|\.jks|proxy|vpn|upload|download|root|hook|xposed|frida|debuggable|bypass|inject|loadlibrary|\.dex|magisk|superuser|getsim|getdevice|imei|imsi|macaddr|location)', re.I)

# 已知加壳/加固 .so 特征
PACKER_SIGS = {
    "梆梆加固(Bangcle)": [b"libshella", b"libshellx", b"libexec.so", b"libshell"],
    "360 加固": [b"libprotect", b"libjiagu", b"libDexHelper", b"lib360"],
    "腾讯乐固(LegU)": [b"libegis", b"libshellx", b"libtup"],
    "网易易盾": [b"libNESec", b"libnesec"],
    "美团(梆梆变体)": [b"libmsaoaidsec"],
    "爱加密": [b"libexec", b"libijiami", b"x86_"],
    "通付盾": [b"libtfs"],
    "娜迦": [b"libnaga"],
    "顶象": [b"libdx"],
    "百度": [b"libbaiduprotect"],
}

def parse_dex_strings(path):
    with open(path, 'rb') as f:
        data = f.read()
    if data[:4] not in (b'dex\n', b'dey\n'):
        return 0, set(), Counter(), set(), {}
    string_ids_size = struct.unpack_from('<I', data, 0x38)[0]
    string_ids_off  = struct.unpack_from('<I', data, 0x3C)[0]
    kw_samples = {}
    urls = set(); hosts = Counter(); ips = set()
    for i in range(string_ids_size):
        off = struct.unpack_from('<I', data, string_ids_off + i*4)[0]
        pos = off
        size = 0; shift = 0
        while True:
            b = data[pos]; pos += 1
            size |= (b & 0x7f) << shift
            if not (b & 0x80): break
            shift += 7
        end = pos
        while data[end] != 0:
            end += 1
        raw = data[pos:end]
        try:
            s = raw.decode('utf-8', 'replace')
        except Exception:
            s = raw.decode('latin-1', 'replace')
        sb = s.encode('utf-8', 'ignore')
        for u in URL_RE.findall(sb):
            urls.add(u.decode('utf-8', 'ignore'))
        for h in HOST_RE.findall(sb):
            hosts[h.decode('utf-8','ignore').lower()] += 1
        for ip in IP_RE.findall(sb):
            ips.add(ip.decode('utf-8','ignore'))
        if len(kw_samples) < 40 and KW_RE.search(sb):
            key = KW_RE.search(sb).group(0).decode('utf-8','ignore').lower()
            kw_samples.setdefault(key, []).append(s[:160])
            if len(kw_samples[key]) > 12:
                kw_samples[key].pop()
    return string_ids_size, urls, hosts, ips, kw_samples

def scan_native(path):
    with open(path, 'rb') as f:
        data = f.read()
    urls = set(); hosts = Counter(); ips = set()
    for u in URL_RE.findall(data):
        urls.add(u.decode('utf-8','ignore'))
    for h in HOST_RE.findall(data):
        hosts[h.decode('utf-8','ignore').lower()] += 1
    for ip in IP_RE.findall(data):
        ips.add(ip.decode('utf-8','ignore'))
    return urls, hosts, ips

report = []
r = report.append
z = zipfile.ZipFile(APK)
names = z.namelist()
r("# WiFi万能钥匙 5.2.20 — 静态逆向拆解报告\n")
r(f"- 文件: `{APK}`\n- 大小: {os.path.getsize(APK):,} bytes ({os.path.getsize(APK)/1024/1024:.1f} MB)\n")
r(f"- APK 内条目总数: {len(names)}\n")

# 目录与扩展统计
dirs = Counter(n.split('/')[0] for n in names)
exts = Counter(n.rsplit('.',1)[-1].lower() if '.' in n else '<none>' for n in names)
r("\n## 1. 包结构概览\n")
r("- 顶层目录: " + ", ".join(f"`{k}/`({v})" for k,v in dirs.most_common(12)) + "\n")
r("- 扩展分布(Top): " + ", ".join(f".{k}={v}" for k,v in exts.most_common(12)) + "\n")

# DEX
dex_names = [n for n in names if re.search(r'(^|/)classes\d*\.dex$', n)]
r(f"- DEX 文件: {len(dex_names)} 个 -> " + ", ".join(dex_names) + "\n")

# native libs
so_names = [n for n in names if n.endswith('.so')]
r(f"- 原生库(.so): {len(so_names)} 个\n")
packer_hits = []
for so in so_names:
    blob = so.lower().encode()
    for pname, sigs in PACKER_SIGS.items():
        if any(s in blob for s in sigs):
            packer_hits.append((so, pname))
if packer_hits:
    r("- ⚠️ 疑似加壳/加固特征(.so):\n")
    for so, p in packer_hits:
        r(f"  - `{so}` -> **{p}**\n")
else:
    r("- 未发现已知加固 .so 特征（或自定义/无壳）\n")

r("\n## 2. AndroidManifest 解析\n")
manifest_xml = None
for n in names:
    if n.endswith('AndroidManifest.xml'):
        manifest_xml = n; break
try:
    import pyaxmlparser
    apk = pyaxmlparser.APK(APK)
    r(f"- Package: `{apk.get_package()}`\n")
    try: r(f"- VersionName: {apk.get_androidversion_name()}\n")
    except Exception as e: r(f"- VersionName: (解析失败 {e})\n")
    try: r(f"- Min SDK: {apk.get_min_sdk_version()}  | Target SDK: {apk.get_target_sdk_version()}\n")
    except Exception as e: r(f"- SDK: (解析失败 {e})\n")
    perms = apk.get_permissions() or []
    r(f"- 权限总数: {len(perms)}\n")
    # 风险权限高亮
    RISK = re.compile(r'(INTERNET|ACCESS_WIFI_STATE|CHANGE_WIFI_STATE|CHANGE_NETWORK_STATE|ACCESS_NETWORK_STATE|READ_PHONE_STATE|READ_CONTACTS|WRITE_CONTACTS|READ_SMS|RECEIVE_SMS|SEND_SMS|READ_EXTERNAL|WRITE_EXTERNAL|GET_ACCOUNTS|ACCESS_FINE_LOCATION|ACCESS_COARSE_LOCATION|CAMERA|RECORD_AUDIO|READ_LOGS|SYSTEM_ALERT_WINDOW|REQUEST_INSTALL_PACKAGES|PACKAGE_USAGE_STATS|WRITE_SETTINGS|BIND_ACCESSIBILITY|RECEIVE_BOOT_COMPLETED|WAKE_LOCK)', re.I)
    risky = [p for p in perms if RISK.search(p)]
    r(f"- 🔴 高危/敏感权限 ({len(risky)}):\n")
    for p in risky:
        r(f"  - `{p}`\n")
    r(f"- 其余权限({len(perms)-len(risky)}): " + ", ".join(f"`{p}`" for p in perms if p not in risky) + "\n")
    acts = apk.get_activities() or []
    srvs = apk.get_services() or []
    recvs = apk.get_receivers() or []
    provs = apk.get_providers() or []
    r(f"- 组件: Activity={len(acts)} Service={len(srvs)} Receiver={len(recvs)} Provider={len(provs)}\n")
except Exception as e:
    r(f"- ⚠️ pyaxmlparser 解析失败: {e}\n")

# network security config
nsc = [n for n in names if 'network_security' in n.lower()]
r(f"- network_security_config: {nsc if nsc else '未找到（或内置默认）'}\n")

r("\n## 3. DEX 字符串提取（网络与关键字）\n")
all_urls=set(); all_hosts=Counter(); all_ips=set(); all_kw={}
total_strings=0
for dn in dex_names:
    dp = os.path.join(TMP, os.path.basename(dn))
    with open(dp,'wb') as f:
        f.write(z.read(dn))
    cnt, urls, hosts, ips, kw = parse_dex_strings(dp)
    total_strings += cnt
    all_urls |= urls; all_hosts += hosts; all_ips |= ips
    for k,v in kw.items():
        all_kw.setdefault(k, [])
        for s in v:
            if s not in all_kw[k]:
                all_kw[k].append(s)
        all_kw[k] = all_kw[k][:12]
r(f"- DEX 字符串总量(估): {total_strings:,}\n")
r(f"- 提取 http(s) URL: {len(all_urls)} 条（去重）\n")
r(f"- 提取主机域名: {len(all_hosts)} 个（去重）\n")
r(f"- 提取 IP(含端口): {len(all_ips)} 个\n")

# 划分 http vs https
http_urls = [u for u in all_urls if u.lower().startswith('http://')]
https_urls = [u for u in all_urls if u.lower().startswith('https://')]
r(f"  - 其中 🔴 明文 http:// {len(http_urls)} 条 / https:// {len(https_urls)} 条\n")
if http_urls:
    r("\n### 3.1 明文(http)端点（不安全传输，重点关注）\n")
    for u in sorted(http_urls)[:60]:
        r(f"  - `{u}`\n")

r("\n### 3.2 高频域名 Top 40（疑似自有/SDK 服务）\n")
for h,c in all_hosts.most_common(40):
    flag = ""
    if any(k in h for k in ('api','sdk','open','gw','cloud','server','service','upload','data','stat','log','report','m.','h5','pay','auth','acc','user','account','wifi','config','cdn','push')):
        flag = " ★"
    r(f"  - `{h}` ({c}){flag}\n")

r("\n### 3.3 IP 地址（含端口）\n")
for ip in sorted(all_ips)[:40]:
    r(f"  - `{ip}`\n")

r("\n### 3.4 安全相关关键字命中样例\n")
for k in sorted(all_kw):
    r(f"- **{k}**:\n")
    for s in all_kw[k][:8]:
        r(f"  - `{s}`\n")

r("\n## 4. 原生层(.so)网络字符串扫描\n")
all_nurls=set(); all_nhosts=Counter(); all_nips=set()
for so in so_names:
    sp = os.path.join(TMP, os.path.basename(so))
    with open(sp,'wb') as f:
        f.write(z.read(so))
    u,h,ip = scan_native(sp)
    all_nurls|=u; all_nhosts+=h; all_nips|=ip
r(f"- 原生层 URL: {len(all_nurls)} / 域名: {len(all_nhosts)} / IP: {len(all_nips)}\n")
r("- 原生层高频域名 Top 25:\n")
for h,c in all_nhosts.most_common(25):
    r(f"  - `{h}` ({c})\n")
if all_nurls:
    r("- 原生层明文 http URL 样例:\n")
    for u in sorted(all_nurls)[:30]:
        r(f"  - `{u}`\n")

r("\n## 5. 小结（静态视角）\n")
r("- 本报告为**纯静态分析**：未执行 APK、未重打包、未解密任何资源。\n")
r("- 关注点应集中在：① 敏感权限组合（尤其是 WiFi/网络/电话/存储/定位）② 明文 http 传输（密码/热点凭证可能明文外发）③ 与外部域名的通信目的地 ④ 是否加壳阻碍进一步分析。\n")
r("- 若要深入：需动态分析（Frida/Xposed 抓包 + 运行时 hook）或上 jadx/apktool 做反编译，本环境未装这些工具。\n")

with open(OUT, 'w', encoding='utf-8') as f:
    f.write("\n".join(report))
print("REPORT WRITTEN:", OUT)
print("dex_strings=%d urls=%d hosts=%d ips=%d nso=%d packers=%s" % (
    total_strings, len(all_urls), len(all_hosts), len(all_ips), len(so_names),
    [p for _,p in packer_hits]))
