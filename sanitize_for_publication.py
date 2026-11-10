#!/usr/bin/env python3
"""lifeline_exposure.py の結果を公開用に加工する。

- 削除：org・isp・asn・city・ssl.cert.*・http.html_hash の値（件数分布は summary に残す）
- http.title：製品や一般的な画面名だけを残し、それ以外は "(other titles, redacted)" にまとめる
- クエリ中の回線事業者名：<ISP-A> などに置き換える
- jp_count・jp_rank・country・port・product・version・tag・screenshot.label は残す

使い方: python3 sanitize_jp.py 入力.json [入力2.json ...] -d 出力ディレクトリ
"""
import argparse
import json
import os
import re
import sys

DROP = {"org", "isp", "asn", "city", "region", "ssl.cert.subject.cn", "ssl.cert.issuer.cn",
        "ssl.cert.fingerprint", "ssl.cert.serial", "http.favicon.hash"}
COUNT_ONLY = {"http.html_hash"}
TITLE_KEEP = re.compile(
    r"^(Top|Error 401|401 Unauthorized|401 - Unauthorized|401 Authorization Required|403 Forbidden|"
    r"400 Bad Request|302 Found|301 Moved Permanently|Redirecting\.\.\.|index|Login|Error|-|497|"
    r"XWEB|XWEB PRO|XWEB EVO|Danfoss StoreView|StoreView - Login|AXIS|"
    r"SolarView Air ASP : SolarView Air Cloud Service|.*Network Camera)$")
# クエリ中の回線事業者名を伏せる。CONC_ORGS（lifeline_exposure.py と同じ）に並べた順に <ISP-A>、<ISP-B> … とする
ISP_ALIASES = {f'"{o.strip()}"': f'"<ISP-{chr(65+i)}>"'
               for i, o in enumerate(x for x in os.environ.get("CONC_ORGS", "").split(",") if x.strip())}


def clean_titles(rows):
    keep, other = [], 0
    for x in rows:
        v = str(x["value"]).strip()
        if TITLE_KEEP.match(v):
            keep.append({"value": v, "count": x["count"]})
        else:
            other += x["count"]
    if other:
        keep.append({"value": "(other titles, redacted)", "count": other})
    return keep


def sanitize(d):
    for name, r in d.get("results", {}).items():
        q = r.get("query", "")
        for k, v in ISP_ALIASES.items():
            q = q.replace(k, v)
        r["query"] = q
        f = r.get("facets") or {}
        for k in list(f):
            if k in DROP:
                del f[k]
            elif k in COUNT_ONLY:
                vals = f[k]
                if vals and isinstance(vals[0], dict):
                    vals = sorted((x["count"] for x in vals), reverse=True)
                f[k] = vals
            elif k == "http.title":
                f[k] = clean_titles(f[k])
    d["sanitized"] = {"tool": "sanitize_jp.py",
                      "removed": sorted(DROP), "count_only": sorted(COUNT_ONLY),
                      "titles": "製品名・一般的な画面名以外は (other titles, redacted) にまとめた",
                      "isp_in_queries": "回線事業者名は <ISP-A> などに置き換えた"}
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+")
    ap.add_argument("-d", "--outdir", default=".")
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)
    for p in a.inputs:
        d = sanitize(json.load(open(p)))
        base = os.path.basename(p)
        base = base.replace(".json", "_public.json")
        out = os.path.join(a.outdir, base)
        if os.path.exists(out):
            sys.exit(f"{out} は既に存在します。")
        json.dump(d, open(out, "w"), ensure_ascii=False, indent=1)
        print("saved", out)


if __name__ == "__main__":
    main()
