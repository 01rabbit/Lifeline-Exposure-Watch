#!/usr/bin/env python3
"""主要な指標を毎日1回数え、1行ずつ JSONL に追記する（定点観測用）。

lifeline_exposure.py と同じく Shodan の count API だけを使う。ファセットは取らないので、
回線事業者名などは出力に含まれない。そのまま公開してよい形式にしてある。

使い方:
    read -s SHODAN_API_KEY && export SHODAN_API_KEY
    python3 daily_watch.py                     # daily_watch.jsonl に追記し、前回との差を表示
    python3 daily_watch.py -f other.jsonl
    python3 daily_watch.py --pv-discover       # 国内の太陽光・エネルギー監視画面のタイトルを探す（内部用）

macOS で毎朝自動で動かす場合は、API キーをキーチェーンに入れておき、cron などから
    SHODAN_API_KEY=$(security find-generic-password -s shodan -w) python3 daily_watch.py
のように呼び出す（API キーを crontab に直接書かない）。
"""
import argparse
import datetime
import json
import os
import sys
import time

try:
    import shodan
except ImportError:
    sys.exit("shodan ライブラリがありません。`pip install -r requirements.txt` を実行してください。")

N = "-tag:cloud -tag:honeypot"
# (名前, 検索条件)。{d1} は「実行日の前日以降」に置き換える
WATCH = [
    # 日本：制御機器
    ("ics_jp",              f"tag:ics country:JP {N}"),
    ("ics_jp_d1",           f"tag:ics country:JP {N} {{d1}}"),
    ("ics_jp_p102",         "tag:ics country:JP port:102"),
    ("ics_jp_lantronix",    "tag:ics country:JP port:30718"),
    ("ics_jp_codesys",      "tag:ics country:JP port:2455"),
    ("ics_jp_melsec",       "tag:ics country:JP port:5006,5007"),
    ("ics_jp_omron",        "tag:ics country:JP port:9600"),
    ("vnc_noauth_jp",       '"authentication disabled" "RFB" country:JP'),
    # 日本：SolarView
    ("solarview_html_jp",   'http.html:"SolarView" country:JP'),
    ("solarview_top_jp",    'http.html:"SolarView" http.title:"Top" country:JP'),
    ("solarview_auth_jp",   '"SolarView" country:JP'),
    ("solarview_html_d1",   'http.html:"SolarView" country:JP {d1}'),
    # 日本：冷蔵設備（おとりの増減も含めて見る）
    ("xweb_jp",             'http.title:"XWEB" country:JP'),
    ("xweb_jp_ssl",         'http.title:"XWEB" country:JP ssl:true'),
    ("storeview_jp",        'http.title:"StoreView" country:JP'),
    ("storeview_jp_clean",  f'http.title:"StoreView" country:JP {N}'),
    ("storeview_jp_ssl",    'http.title:"StoreView" country:JP ssl:true'),
    ("xweb_jp_clean",       f'http.title:"XWEB" country:JP {N}'),
    # 比較：世界と米国
    ("ics_world",           f"tag:ics {N}"),
    ("ics_us",              f"tag:ics country:US {N}"),
    ("micrologix_world",    '"MicroLogix"'),
    ("micrologix_us",       '"MicroLogix" country:US'),
    ("micrologix_world_clean", f'"MicroLogix" {N}'),
    ("unitronics_ics_world", "tag:ics port:20256"),
    ("xweb_world",          f'http.title:"XWEB" {N}'),
    ("xweb_world_ssl",      f'http.title:"XWEB" {N} ssl:true'),
    ("storeview_world",     f'http.title:"StoreView" {N}'),
]

# 国内の太陽光・エネルギー監視の画面を、タイトルの集計から洗い出す（内部用。タイトルに発電所名が入ることがある）
PV_DISCOVER = [
    ("title_hatsuden",  'http.title:"発電" country:JP'),
    ("title_taiyoukou", 'http.title:"太陽光" country:JP'),
    ("title_solar",     'http.title:"solar" country:JP'),
    ("title_pv",        'http.title:"PV" country:JP'),
    ("title_kanshi",    'http.title:"監視" country:JP'),
    ("html_pcs",        'http.html:"パワーコンディショナ" country:JP'),
    ("html_taiyoukou",  'http.html:"太陽光" country:JP'),
    ("html_hems",       'http.html:"HEMS" country:JP'),
    ("html_chikuden",   'http.html:"蓄電" country:JP'),
]


def count(api, q, facets=None):
    for i in range(3):
        try:
            return api.count(q, facets=facets), None
        except shodan.APIError as e:
            err = str(e)
            time.sleep(2 * (i + 1))
    return None, err


def main():
    ap = argparse.ArgumentParser(description="主要指標の日次定点観測（Shodan count API のみ）")
    ap.add_argument("-f", "--file", default="daily_watch.jsonl", help="追記先（既定: daily_watch.jsonl）")
    ap.add_argument("--pv-discover", action="store_true", help="国内の太陽光・エネルギー監視画面のタイトルを探す（内部用）")
    args = ap.parse_args()

    key = os.environ.get("SHODAN_API_KEY")
    if not key:
        sys.exit("環境変数 SHODAN_API_KEY が設定されていません。")
    api = shodan.Shodan(key)
    today = datetime.date.today()
    d1 = f"after:{(today - datetime.timedelta(days=1)).strftime('%d/%m/%Y')}"

    if args.pv_discover:
        fn = f"pv_discover_{time.strftime('%Y%m%d_%H%M%S')}.json"
        out = {"tool": "daily_watch --pv-discover", "run_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "results": {}}
        for name, q in PV_DISCOVER:
            r, err = count(api, q, [("http.title", 50), ("port", 10), ("product", 10)])
            out["results"][name] = {"query": q, "error": err} if r is None else {"query": q, "total": r["total"], "facets": r.get("facets", {})}
            print(f"{name:18s} {r['total'] if r else 'ERROR'}", flush=True)
            time.sleep(1.1)
        json.dump(out, open(fn, "w"), ensure_ascii=False, indent=1)
        print(f"保存しました: {fn}（タイトルに発電所名などが入るため、公開しないこと）")
        return

    prev = None
    if os.path.exists(args.file):
        lines = [l for l in open(args.file) if l.strip()]
        if lines:
            prev = json.loads(lines[-1])
    rec = {"date": today.isoformat(), "run_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "d1": d1, "counts": {}, "errors": {}}
    for name, q in WATCH:
        r, err = count(api, q.replace("{d1}", d1))
        if r is None:
            rec["errors"][name] = err
        else:
            rec["counts"][name] = r["total"]
        time.sleep(1.1)
    with open(args.file, "a") as fp:
        fp.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"{'指標':24s} {'今回':>9s} {'前回比':>8s}")
    for name, _ in WATCH:
        v = rec["counts"].get(name)
        p = (prev or {}).get("counts", {}).get(name)
        diff = f"{v - p:+d}" if (v is not None and p is not None) else ""
        print(f"{name:24s} {v if v is not None else 'ERROR':>9} {diff:>8s}")
    print(f"追記しました: {args.file}")


if __name__ == "__main__":
    main()
