#!/bin/bash
# daily_watch.py を macOS の launchd で毎朝自動実行するための設定スクリプト。
#
# - 作業フォルダ：~/lifeline-watch（~/Documents は macOS のプライバシー保護で
#   自動実行からの書き込みが拒否されることがあるため、ホーム直下に置く）
# - API キー：キーチェーンに保存し、実行のたびに読み出す（ファイルや設定には書かない）
# - 実行時刻：毎朝 7:13。Mac が眠っていた場合は、起動したときに実行される
#
# 使い方（このスクリプトがあるフォルダで）:
#   bash install_macos.sh
# 取り消し:
#   bash uninstall_macos.sh
set -euo pipefail

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"   # リポジトリのフォルダ（daily_watch.py がある場所）
WORK="$HOME/lifeline-watch"
LABEL="com.mrrabbit.lifeline-watch"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
KC_SERVICE="lifeline-watch-shodan"
HOUR=7
MINUTE=13

echo "== 1/5 作業フォルダを用意します: $WORK"
mkdir -p "$WORK/logs"
cp "$SRC_DIR/daily_watch.py" "$WORK/"
cp "$SRC_DIR/requirements.txt" "$WORK/"

echo "== 2/5 Python の仮想環境を作り、shodan ライブラリを入れます"
if [ ! -x "$WORK/.venv/bin/python" ]; then
  python3 -m venv "$WORK/.venv"
fi
"$WORK/.venv/bin/pip" install -q --upgrade pip
"$WORK/.venv/bin/pip" install -q -r "$WORK/requirements.txt"

echo "== 3/5 Shodan の API キーをキーチェーンに保存します"
if security find-generic-password -s "$KC_SERVICE" -a "$USER" >/dev/null 2>&1; then
  echo "   既に保存されています（入れ直す場合は uninstall_macos.sh を実行してから、もう一度実行してください）"
else
  echo "   「password data for new item」と聞かれたら API キーを貼り付けて Enter（2回聞かれます。画面には表示されません）"
  # -w を最後に値なしで置くと対話入力になり、キーがコマンドの引数（ps で見える）に残らない
  security add-generic-password -s "$KC_SERVICE" -a "$USER" -U -w
  echo "   保存しました"
fi

echo "== 4/5 実行用のスクリプトを作ります"
cat > "$WORK/run_daily.sh" <<EOF
#!/bin/bash
# launchd から呼ばれる。API キーはキーチェーンから読み出し、環境変数としてだけ渡す。
cd "$WORK"
export SHODAN_API_KEY="\$(security find-generic-password -s "$KC_SERVICE" -a "\$USER" -w 2>/dev/null)"
if [ -z "\$SHODAN_API_KEY" ]; then
  echo "\$(date '+%F %T') キーチェーンから API キーを読めませんでした" >&2
  exit 1
fi
echo "== \$(date '+%F %T') 実行開始"
"$WORK/.venv/bin/python" "$WORK/daily_watch.py" -f "$WORK/daily_watch.jsonl"
EOF
chmod 700 "$WORK/run_daily.sh"

echo "== 5/5 launchd に登録します（毎朝 ${HOUR}:$(printf %02d $MINUTE)）"
mkdir -p "$HOME/Library/LaunchAgents"
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array><string>/bin/bash</string><string>$WORK/run_daily.sh</string></array>
  <key>StartCalendarInterval</key>
  <dict><key>Hour</key><integer>$HOUR</integer><key>Minute</key><integer>$MINUTE</integer></dict>
  <key>StandardOutPath</key><string>$WORK/logs/daily.log</string>
  <key>StandardErrorPath</key><string>$WORK/logs/daily.err</string>
</dict>
</plist>
EOF
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"

echo
echo "設定が終わりました。今日の分（基準日）を今すぐ1回実行します。"
echo "キーチェーンへのアクセス許可を求められたら「常に許可」を選んでください。"
launchctl kickstart "gui/$(id -u)/$LABEL"
sleep 45
echo "---- ログ（最後の30行） ----"
tail -n 30 "$WORK/logs/daily.log" 2>/dev/null || true
tail -n 5 "$WORK/logs/daily.err" 2>/dev/null || true
echo
echo "記録: $WORK/daily_watch.jsonl"
