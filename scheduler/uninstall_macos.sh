#!/bin/bash
# install_macos.sh・install_weekly_sv_macos.sh で登録した自動実行を止め、キーチェーンの API キーを削除する。
# 記録（~/lifeline-watch/daily_watch.jsonl、~/lifeline-watch/sv_versions/）は残す。
for LABEL in com.mrrabbit.lifeline-watch com.mrrabbit.lifeline-watch.sv-weekly; do
  launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null && echo "自動実行を止めました: $LABEL" || echo "登録されていませんでした: $LABEL"
  rm -f "$HOME/Library/LaunchAgents/$LABEL.plist"
done
security delete-generic-password -s "lifeline-watch-shodan" -a "$USER" >/dev/null 2>&1 && echo "キーチェーンの API キーを削除しました" || true
echo "記録は ~/lifeline-watch に残っています"
