#!/bin/bash
# SolarView のファームウェアの版の分布（daily_watch.py --sv-versions）を、週1回自動で数える設定。
# install_macos.sh を先に実行し、~/lifeline-watch の仮想環境とキーチェーンの API キーができていることが前提。
#
# - 実行時刻：毎週月曜 7:31（Mac が眠っていた場合は、起動したときに実行される）
# - 出力：~/lifeline-watch/sv_versions/sv_versions_YYYYMMDD_HHMMSS.json
#   （count API のみ。IP アドレスは含まず、HTML ハッシュは値を捨てて件数だけを残す）
# - 修正版（Ver.6.00 以上）が現れるか、Basic 認証の件数が増えるかを追うのが目的
#
# 使い方（このスクリプトがあるフォルダで）:
#   bash install_weekly_sv_macos.sh
# 取り消し:
#   bash uninstall_macos.sh   （毎日の分と一緒に止まる）
set -euo pipefail

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$HOME/lifeline-watch"
LABEL="com.mrrabbit.lifeline-watch.sv-weekly"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
KC_SERVICE="lifeline-watch-shodan"
WEEKDAY=1   # 1 = 月曜
HOUR=7
MINUTE=31

if [ ! -x "$WORK/.venv/bin/python" ]; then
  echo "先に install_macos.sh を実行してください（$WORK/.venv がありません）" >&2
  exit 1
fi
if ! security find-generic-password -s "$KC_SERVICE" -a "$USER" >/dev/null 2>&1; then
  echo "キーチェーンに API キーがありません。先に install_macos.sh を実行してください" >&2
  exit 1
fi

echo "== 1/3 最新の daily_watch.py を配置します"
cp "$SRC_DIR/daily_watch.py" "$WORK/"
mkdir -p "$WORK/sv_versions" "$WORK/logs"

echo "== 2/3 実行用のスクリプトを作ります"
cat > "$WORK/run_weekly_sv.sh" <<EOF
#!/bin/bash
cd "$WORK/sv_versions"
export SHODAN_API_KEY="\$(security find-generic-password -s "$KC_SERVICE" -a "\$USER" -w 2>/dev/null)"
if [ -z "\$SHODAN_API_KEY" ]; then
  echo "\$(date '+%F %T') キーチェーンから API キーを読めませんでした" >&2
  exit 1
fi
echo "== \$(date '+%F %T') 実行開始"
"$WORK/.venv/bin/python" "$WORK/daily_watch.py" --sv-versions
EOF
chmod 700 "$WORK/run_weekly_sv.sh"

echo "== 3/3 launchd に登録します（毎週月曜 ${HOUR}:$(printf %02d $MINUTE)）"
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array><string>/bin/bash</string><string>$WORK/run_weekly_sv.sh</string></array>
  <key>StartCalendarInterval</key>
  <dict><key>Weekday</key><integer>$WEEKDAY</integer><key>Hour</key><integer>$HOUR</integer><key>Minute</key><integer>$MINUTE</integer></dict>
  <key>StandardOutPath</key><string>$WORK/logs/sv_weekly.log</string>
  <key>StandardErrorPath</key><string>$WORK/logs/sv_weekly.err</string>
</dict>
</plist>
EOF
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
launchctl print "gui/$(id -u)/$LABEL" >/dev/null && echo "登録しました。次回は月曜 ${HOUR}:$(printf %02d $MINUTE) に実行されます。"
echo "今すぐ1回試す場合: launchctl kickstart gui/$(id -u)/$LABEL"
echo "記録: $WORK/sv_versions/"
