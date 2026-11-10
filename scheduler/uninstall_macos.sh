#!/bin/bash
# install_macos.sh で登録した自動実行を止め、キーチェーンの API キーを削除する。
# 記録（~/lifeline-watch/daily_watch.jsonl）は残す。
LABEL="com.mrrabbit.lifeline-watch"
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null && echo "自動実行を止めました" || echo "自動実行は登録されていませんでした"
rm -f "$HOME/Library/LaunchAgents/$LABEL.plist"
security delete-generic-password -s "lifeline-watch-shodan" -a "$USER" >/dev/null 2>&1 && echo "キーチェーンの API キーを削除しました" || true
echo "記録は ~/lifeline-watch に残っています"
