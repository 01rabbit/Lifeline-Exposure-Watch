#!/usr/bin/env python3
"""日本国内でインターネットに露出している制御・監視機器の件数を、Shodan の count API だけで計測する。

世界の事例（2023〜2026年）で実際に狙われた機器の種類ごとに、
  (1) 全世界の件数と国別の内訳（日本が何位か、件数の規模）
  (2) 日本国内の件数と、ポート・製品・タグ・回線事業者の内訳
を数えて JSON に保存する。

- 使うのは /shodan/host/count だけ。検索クレジットは消費しない。
- IP アドレスやホスト名は取得しない。機器への接続や認証の試行もしない。
- 件数は「実機の台数」ではない。おとり（ハニーポット）や、同じ機器の複数ポートを含む。
- 出力には回線事業者名（org）が入る。公開するときは sanitize_for_publication.py を必ず通すこと。

使い方:
    read -s SHODAN_API_KEY && export SHODAN_API_KEY
    python3 lifeline_exposure.py                 # 本計測
    python3 lifeline_exposure.py --discover      # 日本の tag:ics の製品・ポート内訳だけを見る（クエリ調整用）
    python3 lifeline_exposure.py --followup      # tag:ics のポート別内訳、BACnet・XWEB・SolarView の確認
    python3 lifeline_exposure.py --round3        # SolarView の詳細、回線事業者の集中の確認
    python3 lifeline_exposure.py -o result.json

--round3 の「集中の確認」は、環境変数 CONC_ORGS に回線事業者名（Shodan の org 表記、カンマ区切り）を
設定したときだけ実行する。事業者名はコードに書かない。
    CONC_ORGS="Example ISP,Example ISP Inc." python3 lifeline_exposure.py --round3
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

NOISE = "-tag:cloud -tag:honeypot"

# 全世界のクエリで使う集計。日本の順位と規模を見るため国を多めに取る
WORLD = [("country", 50)]
# 日本のクエリで使う集計。org は回線の種別（携帯回線か固定回線か）を見るためで、公開用では削除する
JP = [("port", 15), ("product", 15), ("org", 20), ("tag", 10), ("http.title", 10)]

# (名前, 検索条件, 事例との対応, 確度)
# 確度: ok = 一般的に使われる書き方 / check = 一致範囲を --discover の結果で確かめてから使う
CATEGORIES = [
    ("ics_all",        "tag:ics",                                  "全体",                           "ok"),
    ("modbus",         "port:502",                                 "FrostyGoop(B3)・Dragos報告",       "ok"),
    ("s7",             "port:102",                                 "AA26-097A更新(S7-1200)",          "ok"),
    ("enip",           "port:44818",                               "AA26-097A(Rockwell)",            "ok"),
    ("micrologix",     '"MicroLogix"',                             "米水道2026-07(A13)",               "check"),
    ("unitronics",     "port:20256",                               "AA23-335A(A2)",                  "ok"),
    ("vnc_noauth",     '"authentication disabled" "RFB"',          "AA25-343A(VNC経由HMI)",            "check"),
    ("vnc_noauth_ics", '"authentication disabled" "RFB" screenshot.label:ics',
                                                                   "AA25-343A(画面がICSと判定されたもの)", "check"),
    ("bacnet",         "port:47808",                               "ビル設備",                         "ok"),
    ("niagara_fox",    "port:1911,4911 fox",                       "ビル設備(Niagara)",                "check"),
    ("melsec",         "port:5006,5007",                           "国内PLC(三菱)",                    "check"),
    ("omron_fins",     "port:9600 OMRON",                          "国内PLC(オムロン)",                 "check"),
    ("dnp3",           "port:20000",                               "電力・水道のRTU",                  "check"),
    ("atg",            '"I20100" port:10001',                      "ATG(B8・B10)",                    "ok"),
    ("moxa_nport",     '"NPort"',                                  "ポーランド2025-12(B9)",             "check"),
    ("solarview",      'http.title:"SolarView"',                   "SolarView(B1・E1)",               "check"),
    ("storeview",      'http.title:"StoreView"',                   "冷蔵(C7)",                        "ok"),
    ("xweb",           'http.title:"XWEB"',                        "冷蔵(C7)",                        "ok"),
]


def count(api, q, facets):
    """ファセットが大きすぎて失敗したら、件数を減らし、それでも駄目なら一つずつ外して再試行する。"""
    last = None
    tries = [facets, [(k, min(n, 20)) for k, n in facets]] if facets else [None]
    for fc in tries:
        try:
            return api.count(q, facets=fc), None
        except shodan.APIError as e:
            last = str(e)
            time.sleep(1.1)
    fc = list(facets or [])
    while fc:
        fc = fc[:-1]
        try:
            return api.count(q, facets=fc or None), f"facets reduced to {[k for k, _ in fc]} ({last})"
        except shodan.APIError as e:
            last = str(e)
            time.sleep(1.1)
    return None, last


def jp_rank(facets):
    """国別ファセットから日本の件数と順位を取り出す。上位50位に入らなければ None。"""
    rows = (facets or {}).get("country", [])
    for i, x in enumerate(rows, 1):
        if x["value"] == "JP":
            return x["count"], i
    return None, None


# 第1回計測（2026-11-10）を受けた追加計測。
# ポート番号だけの検索は「全ポートに応答するホスト」で水増しされるため、tag:ics で実機らしいものに絞る。
# org を検索条件に使うものは集中の確認用で、結果の org 名は公開しない。
FOLLOWUP = [
    # 実機らしいもの（tag:ics）のポート別内訳
    ("ics_jp_p102",     "tag:ics country:JP port:102",      [("org", 10), ("product", 10), ("city", 10)]),
    ("ics_jp_p30718",   "tag:ics country:JP port:30718",    [("org", 10), ("product", 10), ("city", 10)]),
    ("ics_jp_p502",     "tag:ics country:JP port:502",      [("org", 10), ("product", 10), ("city", 10)]),
    ("ics_jp_p2455",    "tag:ics country:JP port:2455",     [("org", 10), ("product", 10)]),
    ("ics_jp_melsec",   "tag:ics country:JP port:5006,5007", [("org", 10), ("product", 10)]),
    ("ics_jp_omron",    "tag:ics country:JP port:9600",     [("org", 10), ("product", 10)]),
    ("ics_jp_enip",     "tag:ics country:JP port:44818",    [("org", 10), ("product", 10)]),
    ("ics_jp_dnp3",     "tag:ics country:JP port:20000",    [("org", 10), ("product", 10)]),
    # 比較用：他国の tag:ics の主なポート
    ("ics_world_port",  "tag:ics -tag:cloud -tag:honeypot", [("port", 30), ("product", 30)]),
    ("ics_us_port",     "tag:ics country:US -tag:cloud -tag:honeypot", [("port", 20)]),
    ("ics_de_port",     "tag:ics country:DE -tag:cloud -tag:honeypot", [("port", 20)]),
    ("ics_kr_port",     "tag:ics country:KR -tag:cloud -tag:honeypot", [("port", 20)]),
    # BACnet：日本が世界3位。実機の応答（Instance ID を含む）かどうかを確かめる
    ("bacnet_jp_inst",  'port:47808 country:JP "Instance ID"', [("org", 10), ("product", 20)]),
    ("bacnet_jp_vendor", 'port:47808 country:JP "Vendor"',   [("org", 10)]),
    ("bacnet_world_inst", 'port:47808 "Instance ID"',        [("country", 20)]),
    # XWEB：日本の165件は単一の事業者で多数のポートに散る。おとりの特徴かを確かめる
    ("xweb_jp_ports",   'http.title:"XWEB" country:JP',     [("port", 100), ("org", 5), ("ssl.cert.subject.cn", 10)]),
    ("xweb_jp_since0111", 'http.title:"XWEB" country:JP after:01/11/2026', None),
    ("xweb_jp_since0104", 'http.title:"XWEB" country:JP after:04/11/2026', None),
    ("xweb_jp_ssl",     'http.title:"XWEB" country:JP ssl:true', None),
    # SolarView：タイトル一致は0件。本文やバナーで探し直す
    ("solarview_any",   '"SolarView"',                      [("country", 10), ("port", 10), ("http.title", 10)]),
    ("solarview_jp",    '"SolarView" country:JP',           [("port", 10), ("http.title", 10), ("org", 10)]),
    ("solarview_html_jp", 'http.html:"SolarView" country:JP', [("port", 10), ("http.title", 10)]),
    # VNC（認証なし）の日本分を、画面判定の種類で見る
    ("vnc_noauth_jp_label", '"authentication disabled" "RFB" country:JP', [("screenshot.label", 20)]),
]


# 第3回：SolarView の露出の詳細と、tag:ics が集中している回線事業者の影響を確かめる。
# Shodan は同じ IP・ポートについて最新のバナーしか持たないため、2024年以前との比較はできない。
# after: で見られるのは「いつ最後に観測されたか」の分布だけである。
CONC_ORGS = [o.strip() for o in os.environ.get("CONC_ORGS", "").split(",") if o.strip()]
CONC_INC = " OR ".join(f'org:"{o}"' for o in CONC_ORGS[:1])   # 代表の1社（集中の内訳を見る）
CONC = " ".join(f'-org:"{o}"' for o in CONC_ORGS)            # 除外用
ROUND3 = [
    # --- SolarView ---
    ("sv_html_jp",         'http.html:"SolarView" country:JP',
                           [("port", 20), ("http.title", 20), ("org", 30), ("product", 10), ("http.html_hash", 200), ("city", 20)]),
    ("sv_banner_jp",       '"SolarView" country:JP',          [("port", 20), ("org", 30), ("product", 10)]),
    ("sv_both_jp",         '"SolarView" http.html:"SolarView" country:JP', None),   # 2つの数え方の重なり
    ("sv_html_top_jp",     'http.html:"SolarView" http.title:"Top" country:JP', [("port", 10), ("http.html_hash", 200)]),
    ("sv_html_401_jp",     'http.html:"SolarView" http.title:"Error 401" country:JP', None),
    ("sv_compact_jp",      'http.html:"SV-CPT" country:JP',  [("http.title", 10), ("http.html_hash", 200)]),
    ("sv_air_jp",          'http.html:"SolarView Air" country:JP', [("http.title", 10)]),
    ("sv_html_ssl_jp",     'http.html:"SolarView" country:JP ssl:true', None),
    ("sv_html_r7",         'http.html:"SolarView" country:JP {r7}', None),
    ("sv_html_r16",        'http.html:"SolarView" country:JP {r16}', None),
    ("sv_html_r30",        'http.html:"SolarView" country:JP {r30}', None),
    ("sv_banner_r16",      '"SolarView" country:JP {r16}', None),
    ("sv_html_honeypot",   'http.html:"SolarView" country:JP tag:honeypot', None),
    ("sv_html_world",      'http.html:"SolarView"',          [("country", 20)]),
    # --- tag:ics の集中の確認 ---
    ("ics_jp_conc_only",   f'tag:ics country:JP {CONC_INC}', [("port", 30), ("product", 20), ("city", 20)]),
    ("ics_jp_conc_r7",     f'tag:ics country:JP {CONC_INC} {{r7}}', None),
    ("ics_jp_excl",        f'tag:ics country:JP {CONC}',     [("port", 30), ("product", 30), ("org", 20)]),
    ("ics_jp_excl_r16",    f'tag:ics country:JP {CONC} {{r16}}', None),
    # 同じ事業者で、制御系以外のポートがどれだけ開いているか（おとりなら多数並ぶ傾向）
    ("conc_p102_all",      f'port:102 country:JP {CONC_INC}', [("product", 10), ("tag", 10)]),
    # --- 実機と見られる国産機器・変換器 ---
    ("melsec_jp_r16",      'tag:ics country:JP port:5006,5007 {r16}', None),
    ("lantronix_jp",       'tag:ics country:JP port:30718',  [("product", 10), ("version", 20)]),
    ("hms_jp",             'tag:ics country:JP product:"HMS Networks"', [("version", 10)]),
]

# 値そのものは保存せず、件数の分布だけを残すファセット（実機を探す手がかりや店舗名になるため）
MASK_FACETS = {"http.html_hash", "ssl.cert.subject.cn", "ssl.cert.fingerprint"}


def build_queries(r16, discover, followup=False, round3=False, r7=None, r30=None):
    if round3:
        rows = ROUND3 if CONC_ORGS else [x for x in ROUND3 if "conc" not in x[0] and "excl" not in x[0]]
        return [(n, q.replace("{r7}", r7).replace("{r16}", r16).replace("{r30}", r30), f, "round3", "ok")
                for n, q, f in rows]
    if followup:
        return [(n, q, f, "followup", "ok") for n, q, f in FOLLOWUP]
    if discover:
        return [
            ("discover_ics_jp",      f"tag:ics country:JP {NOISE}", [("product", 50), ("port", 50), ("tag", 20)], "-", "ok"),
            ("discover_ics_jp_hp",   "tag:ics tag:honeypot country:JP", [("product", 20), ("port", 20)], "-", "ok"),
            ("discover_ics_jp_cloud", "tag:ics tag:cloud country:JP", [("product", 20), ("port", 20)], "-", "ok"),
        ]
    g = []
    for name, q, case, conf in CATEGORIES:
        g.append((f"{name}_world",   f"{q} {NOISE}",                   WORLD, case, conf))
        g.append((f"{name}_jp",      f"{q} {NOISE} country:JP",        JP,    case, conf))
        g.append((f"{name}_jp_r16",  f"{q} {NOISE} country:JP {r16}",  None,  case, conf))
    # おとり・クラウドとして除外された分の規模（日本、tag:ics）
    g.append(("ics_jp_honeypot", "tag:ics tag:honeypot country:JP", None, "除外分", "ok"))
    g.append(("ics_jp_cloud",    "tag:ics tag:cloud country:JP",    None, "除外分", "ok"))
    return g


def main():
    ap = argparse.ArgumentParser(description="日本国内の制御・監視機器の露出件数を Shodan の count API で計測する")
    ap.add_argument("--discover", action="store_true",
                    help="日本の tag:ics の製品・ポート内訳だけを取得する（本計測の前のクエリ調整用）")
    ap.add_argument("--followup", action="store_true",
                    help="第1回計測を受けた追加計測（tag:ics のポート別内訳、BACnet、XWEB、SolarView の確認）")
    ap.add_argument("--round3", action="store_true",
                    help="第3回：SolarView の露出の詳細と、回線事業者の集中の影響を確かめる")
    ap.add_argument("-o", "--output", help="出力ファイル名。既定: jp_ot_<mode>_YYYYmmdd_HHMMSS.json")
    args = ap.parse_args()

    key = os.environ.get("SHODAN_API_KEY")
    if not key:
        sys.exit("環境変数 SHODAN_API_KEY が設定されていません。"
                 "`read -s SHODAN_API_KEY && export SHODAN_API_KEY` で設定してください。")
    api = shodan.Shodan(key)

    mode = "round3" if args.round3 else "followup" if args.followup else "discover" if args.discover else "measure"
    prefix = {"round3": "jp_ot_round3", "followup": "jp_ot_followup",
              "discover": "jp_ot_discover", "measure": "jp_ot"}[mode]
    fn = args.output or f"{prefix}_{time.strftime('%Y%m%d_%H%M%S')}.json"
    if os.path.exists(fn):
        sys.exit(f"{fn} は既に存在します。上書きしないよう終了しました。別の名前を -o で指定してください。")

    today = datetime.date.today()
    ago = lambda n: f"after:{(today - datetime.timedelta(days=n)).strftime('%d/%m/%Y')}"
    r7, r16, r30 = ago(7), ago(16), ago(30)

    out = {
        "tool": "lifeline_exposure",
        "mode": mode,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "run_date": today.isoformat(),
        "windows": {"R7": r7, "R16": r16, "R30": r30},
        "results": {},
    }
    for name, q, facets, case, conf in build_queries(r16, args.discover, args.followup, args.round3, r7, r30):
        t0 = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        r, note = count(api, q, facets)
        if r is None:
            out["results"][name] = {"query": q, "case": case, "confidence": conf, "queried_at": t0, "error": note}
            print(f"{name:24s} ERROR {note}", flush=True)
        else:
            f = r.get("facets", {}) or {}
            summ = {}
            for mk in MASK_FACETS & set(f):
                cnts = sorted((x["count"] for x in f[mk]), reverse=True)
                summ[f"{mk}_distinct"] = len(cnts)
                summ[f"{mk}_top1_share"] = round(cnts[0] / r["total"], 3) if cnts and r["total"] else None
                f[mk] = cnts   # 値は捨て、件数の分布だけを残す
            rec = {"summary": summ,"query": q, "case": case, "confidence": conf, "queried_at": t0,
                   "total": r["total"], "facets": f, "note": note}
            line = f"{name:24s} {r['total']:>9}"
            if name.endswith("_world"):
                jc, jr = jp_rank(f)
                rec["jp_count"], rec["jp_rank"] = jc, jr
                line += f"  JP={jc} (#{jr})" if jc is not None else "  JP=圏外(50位以下)"
            out["results"][name] = rec
            print(line + (f"  [{note}]" if note else "") + ("  ※要確認" if conf == "check" else ""), flush=True)
        time.sleep(1.1)

    out["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    with open(fn, "w") as fp:
        json.dump(out, fp, ensure_ascii=False, indent=1)
    print(f"保存しました: {fn}")
    print("注意: このファイルには回線事業者名が含まれます。公開前に sanitize_for_publication.py を通してください。")


if __name__ == "__main__":
    main()
