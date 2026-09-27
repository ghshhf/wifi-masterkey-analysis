#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从关键 native .so 抽取可打印字符串并筛选敏感模式。"""
import os, re

LIB = r"E:/xmanbian/_tools/wifi_apktool_out/lib"
TARGETS = [
    "libcoreManger_new.so","libcore_daemon_new.so","libcxCoreManger.so",
    "libdaemon_api20.so","libdaemon_api21.so","libwdid_clean_new.so",
    "libphonemark.so","libadinfo.so","libDXRisk-v7_7_1r_f9c632ad.so",
    "libtobEmbedEncrypt.so","libturingau.so","libCtaApiLib.so",
    "liboctopus.so","libods.so","libpatch.so","libphantom.so",
    "libqcloud_asr_realtime.so","libindoor.so","libmaparmor.so",
    "libpanglearmor.so","libsentry.so","libmetis.so","libmmkv.so",
]
PAT = re.compile(rb'(?:https?://[^\s\x00-\x1f"\'<>]{5,}|/[\w./-]{4,}\.(?:php|json|do|api|jsp|html)|'
                 rb'[A-Za-z0-9_.-]+\.(?:com|cn|net|org|io|me|tv|info|biz)(?:[:/][^\s\x00-\x1f"\'<>]*)?|'
                 rb'(?:wifi|password|passwd|pwd|upload|collect|device|imei|imsi|daemon|heartbeat|'
                 rb'location|secret|key|token|encrypt|decrypt|root|frida|xposed|hook|inject)[A-Za-z0-9_/.-]{0,40})',
                 re.I)
OUT = r"E:/xmanbian/tools_and_notes/wifi_so_strings.md"
seen = {}
with open(OUT, "w", encoding="utf-8") as o:
    o.write("# 关键 native 库字符串取证\n\n")
    for fn in TARGETS:
        for arch in ("arm64-v8a","armeabi-v7a"):
            fp = os.path.join(LIB, arch, fn)
            if not os.path.exists(fp): 
                continue
            o.write(f"\n## {fn} ({arch}, {os.path.getsize(fp)//1024}KB)\n")
            try:
                data = open(fp,"rb").read()
            except Exception as e:
                o.write(f"  (read err {e})\n"); continue
            hits = set()
            for m in PAT.finditer(data):
                s = m.group(0).decode("latin1","ignore")
                if len(s) >= 5:
                    hits.add(s)
            for s in sorted(hits)[:120]:
                o.write(f"- `{s}`\n")
            o.write(f"\n  (unique 命中 {len(hits)})\n")
print("done ->", OUT)
