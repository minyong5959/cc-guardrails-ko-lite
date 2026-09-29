#!/usr/bin/env bash
# 시크릿 유출 가드 (PreToolUse / Write, Edit, MultiEdit, NotebookEdit, Bash)
#
# 1) 파일 쓰기(Write/Edit/MultiEdit/NotebookEdit)
#    - 알려진 토큰 패턴(개인 키, 클라우드 액세스 키, 서비스 토큰)이 내용에 있으면 차단
#      단, .env / .env.* (예시 파일 제외) 처럼 원래 시크릿을 두는 파일은 허용 -> 커밋 단계에서 막는다
#    - "PASSWORD = ..." 같은 일반 할당 패턴은 오탐이 많아 확인(ask)만
# 2) git add / git commit (Bash)
#    - 시크릿 파일명(.env, *.pem, id_rsa 등)을 스테이징/커밋하려 하면 차단
#    - 스테이징된 변경(또는 commit -a 의 추적 파일 변경)에 토큰 패턴이 있으면 차단
#
# 끄기: CCG_DISABLE=secret-leak-guard

HOOK_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib/common.sh
. "$HOOK_DIR/lib/common.sh" 2>/dev/null || { echo "[cc-guardrails-ko] lib/common.sh 없음" >&2; exit 1; }

ccg_init secret-leak-guard

TOOL=$(ccg_get '.tool_name')
CWD=$(ccg_get '.cwd')
[ -n "$CWD" ] || CWD=$(pwd)

GENERIC_RE='(api[_-]?key|secret|token|passwd|password|private[_-]?key|client[_-]?secret)[a-z0-9_]*["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9/+_.@!#%^&*-]{12,}'
PLACEHOLDER_RE='(x{4,}|\*{4,}|<[^>]*>|\$\{|\$[A-Z_]+|changeme|change_me|your[_-]|example|dummy|placeholder|sample|redacted|test[_-]?(key|token|secret)|process\.env|os\.environ|getenv)'

match_secret() {
  # stdin 내용에서 확신도 높은 패턴 첫 매치를 출력 (값은 앞 8자만)
  grep -Eo -e "$CCG_SECRET_RE" 2>/dev/null | head -n 1 | cut -c1-8
}

env_file_allowed() {
  local b=${1##*/}
  case "$b" in
    .env.example|.env.sample|.env.template|.env.dist) return 1 ;;
    .env|.env.*) return 0 ;;
  esac
  return 1
}

check_write() {
  local path content hit generic
  path=$(ccg_get '.tool_input.file_path // .tool_input.notebook_path')
  content=$(printf '%s' "$CCG_INPUT" | jq -r '
    [ .tool_input.content, .tool_input.new_string, .tool_input.new_source,
      ((.tool_input.edits // [])[]? | .new_string) ] | map(select(. != null)) | join("\n")' 2>/dev/null)
  [ -n "$content" ] || exit 0
  env_file_allowed "$path" && exit 0

  hit=$(printf '%s' "$content" | match_secret)
  if [ -n "$hit" ]; then
    ccg_deny "쓰려는 내용에 시크릿으로 보이는 값(${hit}...)이 있습니다. 파일: ${path##*/}. 값은 환경변수나 시크릿 매니저에서 읽도록 코드를 바꾸고, 값 자체는 .env(커밋 제외)에 두세요."
  fi

  generic=$(printf '%s' "$content" | grep -Eio -e "$GENERIC_RE" 2>/dev/null | grep -Eiv -e "$PLACEHOLDER_RE" | head -n 1)
  if [ -n "$generic" ]; then
    ccg_ask "쓰려는 내용에 비밀번호·키 할당으로 보이는 줄이 있습니다(${generic%%[=:]*}). 실제 값이면 환경변수로 옮기세요. 예시 값이면 승인해도 됩니다."
  fi
  exit 0
}

# git 하위 명령과 -C 경로 파악
git_ctx() {
  local i n w
  n=${#CCG_W[@]}
  i=1
  GDIR="$CWD"
  GSUB=""
  GIDX=0
  while [ "$i" -lt "$n" ]; do
    w=${CCG_W[$i]}
    case "$w" in
      -C)
        case "${CCG_W[$((i + 1))]:-}" in
          /*) GDIR=${CCG_W[$((i + 1))]} ;;
          *) GDIR="$CWD/${CCG_W[$((i + 1))]:-}" ;;
        esac
        i=$((i + 2)); continue ;;
      -c) i=$((i + 2)); continue ;;
      -*) i=$((i + 1)); continue ;;
      *) GSUB=$w; GIDX=$i; return 0 ;;
    esac
  done
}

deny_msg=""

check_git_add() {
  local i n w broad=0 f hit files=""
  n=${#CCG_W[@]}
  i=$((GIDX + 1))
  while [ "$i" -lt "$n" ]; do
    w=${CCG_W[$i]}
    case "$w" in
      -A|--all|.|-u|--update|:/) broad=1 ;;
      -*) ;;
      *) files="$files $w" ;;
    esac
    i=$((i + 1))
  done
  set -f
  for f in $files; do
    if ccg_is_secret_filename "$f"; then
      set +f
      deny_msg="시크릿 파일(${f##*/})을 git 에 추가하려 합니다. .gitignore 에 넣고 예시 파일(.env.example 등)만 커밋하세요."
      return 0
    fi
  done
  set +f
  if [ "$broad" = 1 ]; then
    # 추가될 후보: 무시되지 않은 미추적 파일
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      if ccg_is_secret_filename "$f"; then
        deny_msg="git add 범위에 시크릿 파일(${f##*/})이 포함됩니다. .gitignore 에 추가한 뒤 다시 실행하세요."
        return 0
      fi
      if [ -f "$GDIR/$f" ] && [ "$(wc -c <"$GDIR/$f" 2>/dev/null || echo 0)" -lt 1048576 ]; then
        hit=$(match_secret <"$GDIR/$f")
        if [ -n "$hit" ]; then
          deny_msg="git add 범위의 파일(${f##*/})에 시크릿으로 보이는 값(${hit}...)이 있습니다."
          return 0
        fi
      fi
    done <<EOF
$(git -C "$GDIR" ls-files --others --exclude-standard 2>/dev/null)
EOF
    hit=$(git -C "$GDIR" diff 2>/dev/null | grep -E '^\+' | match_secret)
    if [ -n "$hit" ]; then
      deny_msg="git add 범위의 변경에 시크릿으로 보이는 값(${hit}...)이 있습니다."
    fi
  fi
}

check_git_commit() {
  local f hit all=0 diffs
  ccg_has_word -a --all -am && all=1
  local w
  for w in "${CCG_W[@]}"; do
    case "$w" in -[a-zA-Z]*a*) case "$w" in --*) ;; *) all=1 ;; esac ;; esac
  done
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if ccg_is_secret_filename "$f"; then
      deny_msg="커밋에 시크릿 파일(${f##*/})이 스테이징돼 있습니다. git rm --cached 로 빼고 .gitignore 에 추가하세요."
      return 0
    fi
  done <<EOF
$(git -C "$GDIR" diff --cached --name-only 2>/dev/null)
EOF
  diffs=$(git -C "$GDIR" diff --cached 2>/dev/null)
  if [ "$all" = 1 ]; then
    diffs="$diffs
$(git -C "$GDIR" diff 2>/dev/null)"
  fi
  hit=$(printf '%s\n' "$diffs" | grep -E '^\+' | match_secret)
  if [ -n "$hit" ]; then
    deny_msg="커밋할 변경에 시크릿으로 보이는 값(${hit}...)이 있습니다. 값을 제거하고, 이미 노출된 키라면 폐기·재발급하세요."
  fi
}

check_bash() {
  local cmd seg
  cmd=$(ccg_get '.tool_input.command')
  [ -n "$cmd" ] || exit 0
  while IFS= read -r seg; do
    [ -n "$seg" ] || continue
    ccg_words "$seg"
    [ "$CCG_TOOL" = "git" ] || continue
    git_ctx
    case "$GSUB" in
      add) check_git_add ;;
      commit) check_git_commit ;;
    esac
    [ -n "$deny_msg" ] && ccg_deny "$deny_msg"
  done <<EOF
$(ccg_segments "$cmd")
EOF
  exit 0
}

case "$TOOL" in
  Write|Edit|MultiEdit|NotebookEdit) check_write ;;
  Bash) check_bash ;;
esac
exit 0
