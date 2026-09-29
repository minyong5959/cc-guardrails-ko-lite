# shellcheck shell=bash
# cc-guardrails-ko 공용 함수. 각 훅이 source 한다.
# bash 3.2(macOS 기본) 호환: 연관 배열, ${var,,}, mapfile 을 쓰지 않는다.
#
# 출력 계약 (Claude Code hooks reference 기준)
#   차단(deny)  : stderr 에 사유 + exit 2  -> PreToolUse 는 도구 호출 차단, Claude 가 사유를 본다
#   확인(ask)   : stdout JSON hookSpecificOutput.permissionDecision="ask" + exit 0
#   경고(warn)  : stdout JSON hookSpecificOutput.additionalContext + exit 0 (진행은 허용)
#   통과(allow) : 출력 없이 exit 0 -> 일반 권한 흐름
#   내부 오류   : exit 1 (비차단, 사용자에게 "hook error" 표시). CCG_FAIL_CLOSED=1 이면 exit 2

CCG_NAME="cc-guardrails-ko"
CCG_INPUT=""
CCG_EVENT=""

ccg_internal_error() {
  printf '[%s] 내부 오류: %s (이번 호출은 가드가 적용되지 않았습니다)\n' "$CCG_NAME" "$1" >&2
  if [ "${CCG_FAIL_CLOSED:-0}" = "1" ]; then
    exit 2
  fi
  exit 1
}

# CCG_DISABLE="deploy-target-guard,blocking-watch-nudge" 처럼 훅 이름을 나열하면 해당 훅을 끈다.
ccg_disabled() {
  case ",${CCG_DISABLE:-}," in
    *",$1,"*) return 0 ;;
  esac
  return 1
}

ccg_init() {
  # $1 = 훅 이름
  if ccg_disabled "$1"; then
    exit 0
  fi
  command -v jq >/dev/null 2>&1 || ccg_internal_error "jq 가 설치돼 있지 않습니다"
  CCG_INPUT=$(cat)
  printf '%s' "$CCG_INPUT" | jq -e 'type == "object"' >/dev/null 2>&1 \
    || ccg_internal_error "입력 JSON 을 해석할 수 없습니다"
  CCG_EVENT=$(ccg_get '.hook_event_name')
}

# jq 경로로 값 읽기. 없으면 빈 문자열.
ccg_get() {
  printf '%s' "$CCG_INPUT" | jq -r "($1) // empty" 2>/dev/null
}

ccg_deny() {
  printf '[%s] 차단: %s\n' "$CCG_NAME" "$1" >&2
  exit 2
}

ccg_ask() {
  jq -n --arg r "[$CCG_NAME] $1" '{
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "ask",
      permissionDecisionReason: $r
    }
  }'
  exit 0
}

ccg_warn() {
  local ev="${CCG_EVENT:-PreToolUse}"
  jq -n --arg ev "$ev" --arg m "[$CCG_NAME] $1" '{
    hookSpecificOutput: { hookEventName: $ev, additionalContext: $m }
  }'
  exit 0
}

# 셸 명령을 단순 명령 단위로 쪼갠다: && || ; | & $( ` ( ) 와 줄바꿈 기준.
# 따옴표 안의 구분자도 쪼개지만, 가드 목적상 더 많이 쪼개는 쪽은 안전하다.
ccg_segments() {
  printf '%s\n' "$1" | awk '{ gsub(/\$\(|`|\(|\)|&&|\|\||;|\||&/, "\n"); print }'
}

# 한 세그먼트를 단어 배열로 만든다. 결과:
#   CCG_W      : 래퍼(sudo, env, npx, bash -c 등)와 앞쪽 VAR=값 을 걷어낸 단어 배열
#   CCG_TOOL   : 첫 단어의 basename (firebase-tools -> firebase)
#   CCG_ENVPFX : 걷어낸 VAR=값 들을 공백으로 이은 문자열
ccg_words() {
  local seg raw i n w
  seg=$(printf '%s' "$1" | tr -d "\"'")
  raw=()
  read -r -a raw <<<"$seg"
  n=${#raw[@]}
  i=0
  CCG_ENVPFX=""
  while [ "$i" -lt "$n" ]; do
    w=${raw[$i]}
    case "$w" in
      [A-Za-z_]*=*)
        case "${w%%=*}" in
          *[!A-Za-z0-9_]*) break ;;
        esac
        CCG_ENVPFX="$CCG_ENVPFX $w"
        i=$((i + 1))
        ;;
      sudo|command|exec|time|nohup|env|npx|bunx)
        i=$((i + 1))
        while [ "$i" -lt "$n" ]; do
          case "${raw[$i]}" in
            -*) i=$((i + 1)) ;;
            *) break ;;
          esac
        done
        ;;
      pnpm|yarn|npm)
        case "${raw[$((i + 1))]:-}" in
          dlx|exec) i=$((i + 2)) ;;
          *) break ;;
        esac
        ;;
      bash|sh|zsh|dash)
        if [ "${raw[$((i + 1))]:-}" = "-c" ] || [ "${raw[$((i + 1))]:-}" = "-lc" ]; then
          i=$((i + 2))
        else
          break
        fi
        ;;
      *) break ;;
    esac
  done
  CCG_W=()
  while [ "$i" -lt "$n" ]; do
    CCG_W[${#CCG_W[@]}]=${raw[$i]}
    i=$((i + 1))
  done
  CCG_TOOL=""
  if [ "${#CCG_W[@]}" -gt 0 ]; then
    CCG_TOOL=${CCG_W[0]##*/}
    case "$CCG_TOOL" in
      firebase-tools) CCG_TOOL=firebase ;;
    esac
  fi
}

# CCG_W 안에 플래그가 값과 함께 있는지. 사용: ccg_has_flag --project -P
# 인정 형태: "--project x", "--project=x", "-P x". 값이 비었거나 다음 단어가 플래그면 불인정.
ccg_has_flag() {
  local i n w f next
  n=${#CCG_W[@]}
  i=0
  while [ "$i" -lt "$n" ]; do
    w=${CCG_W[$i]}
    for f in "$@"; do
      if [ "$w" = "$f" ]; then
        next=${CCG_W[$((i + 1))]:-}
        case "$next" in
          ""|-*) ;;
          *) return 0 ;;
        esac
      fi
      case "$w" in
        "$f"=?*) return 0 ;;
      esac
    done
    i=$((i + 1))
  done
  return 1
}

# CCG_W 안에 정확히 일치하는 단어가 있는지.
ccg_has_word() {
  local w f
  for w in "${CCG_W[@]}"; do
    for f in "$@"; do
      [ "$w" = "$f" ] && return 0
    done
  done
  return 1
}

# CCG_W 에서 플래그가 아닌 단어만 공백으로 이어 출력 (첫 단어 제외).
ccg_positional() {
  local i n out
  n=${#CCG_W[@]}
  i=1
  out=""
  while [ "$i" -lt "$n" ]; do
    case "${CCG_W[$i]}" in
      -*) ;;
      *) out="$out ${CCG_W[$i]}" ;;
    esac
    i=$((i + 1))
  done
  printf '%s' "$out"
}

# 알려진 시크릿 패턴 (확신도 높음). grep -E 용.
# shellcheck disable=SC2034 # source 하는 훅이 사용
CCG_SECRET_RE='-----BEGIN ([A-Z]+ )?PRIVATE KEY-----|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}|xox[abposr]-[A-Za-z0-9-]{10,}|sk_live_[0-9A-Za-z]{20,}|rk_live_[0-9A-Za-z]{20,}|AIza[0-9A-Za-z_-]{35}|sk-ant-[A-Za-z0-9_-]{20,}|sk-proj-[A-Za-z0-9_-]{20,}|glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{36}'

# 시크릿이 들어가면 안 되는 파일 이름 (커밋 대상 검사용).
ccg_is_secret_filename() {
  local b
  b=${1##*/}
  case "$b" in
    .env.example|.env.sample|.env.template|.env.dist|*.example|*.sample) return 1 ;;
    .env|.env.*|*.pem|*.p12|*.pfx|*.key|id_rsa|id_ed25519|id_ecdsa|id_dsa|*.keystore|*.jks|credentials.json|service-account*.json) return 0 ;;
  esac
  return 1
}
