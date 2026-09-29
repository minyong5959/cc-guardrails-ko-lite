#!/usr/bin/env bash
# 개인정보(PII) 유출 가드 (PreToolUse / Write, Edit, MultiEdit, NotebookEdit, Bash)
#
# 1) 파일 쓰기(Write/Edit/MultiEdit/NotebookEdit): 쓰려는 내용에 아래 값이 있으면 차단
# 2) git add / git commit (Bash): 추가·커밋될 변경(추가된 줄, 새 파일 내용)에 있으면 차단
#
# 찾는 값 (오탐을 줄이려고 형식 + 검증을 함께 본다)
#   - 주민등록번호·외국인등록번호: YYMMDD-[1-8]NNNNNN (하이픈 생략 허용), 날짜 유효성 + 검증번호
#   - 휴대폰 번호: 010/011/016/017/018/019, +82 10 형식. 010-0000-0000, 010-1234-5678 같은 예시 번호는 제외
#   - 신용카드 번호: 13~19자리, 카드사 번호 대역 + Luhn 검증. 널리 알려진 결제 테스트 카드 번호는 제외
#   - 이메일 주소: 한 번에 서로 다른 주소가 3개 이상이면 차단 (1~2개는 허용). example.com 등 예시 도메인 제외
#   계좌번호·여권번호는 형식이 은행·연도마다 달라 오탐이 많아 검사하지 않는다.
#
# 예외 (둘 다 문서화된 방법)
#   - 테스트 픽스처 경로: 경로에 fixtures/, __fixtures__/, testdata/ 디렉토리가 들어가면 검사하지 않음
#     추가 경로: CCG_PII_ALLOW_PATHS="*/seed/* docs/samples/*" (공백 구분 glob, 저장소 기준 경로에도 적용)
#   - 줄 단위 표시: 같은 줄에 "pii-guard: allow" 가 있으면 그 줄은 검사하지 않음
#
# 조정
#   CCG_PII_EMAIL_THRESHOLD=3   이메일 차단 기준 개수 (기본 3)
#   CCG_PII_RRN_CHECKSUM=1      주민등록번호 검증번호까지 확인 (오탐↓, 단 2020-10 이후 발급 번호는 놓침). 기본 0 = 날짜 형식만
#
# 메시지에는 찾은 값을 가려서(마스킹) 보여 준다. 원문은 출력·저장하지 않는다.
#
# 끄기: CCG_DISABLE=pii-leak-guard

HOOK_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib/common.sh
. "$HOOK_DIR/lib/common.sh" 2>/dev/null || { echo "[cc-guardrails-ko] lib/common.sh 없음" >&2; exit 1; }

ccg_init pii-leak-guard

TOOL=$(ccg_get '.tool_name')
CWD=$(ccg_get '.cwd')
[ -n "$CWD" ] || CWD=$(pwd)

PII_MARKER='pii-guard: allow'
EMAIL_MAX=${CCG_PII_EMAIL_THRESHOLD:-3}
case "$EMAIL_MAX" in ''|*[!0-9]*) EMAIL_MAX=3 ;; esac
RRN_CHECK=${CCG_PII_RRN_CHECKSUM:-0}

# 후보 추출 정규식 (grep -E). 앞뒤 경계 문자까지 잡은 뒤 검증기에서 떼어 낸다.
RRN_RE='(^|[^0-9])[0-9]{2}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])-?[1-8][0-9]{6}([^0-9]|$)'
PHONE_RE='(^|[^0-9])(\+82[- ]?|0)1[016789][- .]?[0-9]{3,4}[- .]?[0-9]{4}([^0-9]|$)'
CARD_RE='(^|[^0-9])([0-9]{13,19}|[0-9]{4}[- ][0-9]{4}[- ][0-9]{4}[- ][0-9]{1,7}|[0-9]{4}[- ][0-9]{6}[- ][0-9]{4,5})([^0-9]|$)'
EMAIL_RE='[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'

# 검증기: 입력 "종류:줄번호:후보" -> 출력 "종류<TAB>마스킹 값<TAB>첫 줄번호<TAB>건수"
# shellcheck disable=SC2016 # awk 프로그램
PII_AWK='
function onlydigits(s) { gsub(/[^0-9]/, "", s); return s }
function samedigits(s,   t) { t = s; gsub(substr(s, 1, 1), "", t); return t == "" }
function rrn_ok(d,   mm, dd, g, w, i, sum, c) {
  if (length(d) != 13) return 0
  mm = substr(d, 3, 2) + 0; dd = substr(d, 5, 2) + 0; g = substr(d, 7, 1) + 0
  if (mm < 1 || mm > 12 || dd < 1 || dd > 31 || g < 1 || g > 8) return 0
  if (mm == 2 && dd > 29) return 0
  if ((mm == 4 || mm == 6 || mm == 9 || mm == 11) && dd > 30) return 0
  if (!chk) return 1
  w = "234567892345"; sum = 0
  for (i = 1; i <= 12; i++) sum += substr(d, i, 1) * substr(w, i, 1)
  if (g <= 4) c = (11 - sum % 11) % 10; else c = (13 - sum % 11) % 10
  return c == substr(d, 13, 1) + 0
}
function luhn(d,   i, n, sum, x, alt) {
  n = length(d); sum = 0; alt = 0
  for (i = n; i >= 1; i--) {
    x = substr(d, i, 1) + 0
    if (alt) { x *= 2; if (x > 9) x -= 9 }
    sum += x; alt = !alt
  }
  return sum % 10 == 0
}
function card_range(d,   n, p1, p2) {
  n = length(d); p1 = substr(d, 1, 1); p2 = substr(d, 1, 2) + 0
  if (p1 == "4") return n == 13 || n == 16 || n == 19
  if ((p2 >= 51 && p2 <= 55) || (p2 >= 22 && p2 <= 27)) return n == 16
  if (p2 == 34 || p2 == 37) return n == 15
  if (p2 == 35 || p2 == 36 || p2 == 30 || p2 == 38) return n >= 14 && n <= 19
  if (p1 == "6") return n >= 16 && n <= 19
  if (p1 == "9") return n == 16
  return 0
}
function mask(s, keep,   i, c, k, out) {
  out = ""; k = 0
  for (i = 1; i <= length(s); i++) {
    c = substr(s, i, 1)
    if (c ~ /[0-9]/) { k++; out = out (k <= keep ? c : "*") } else out = out c
  }
  return out
}
function add(t, m, ln) {
  if (!(t in cnt)) { first[t] = m; line[t] = ln }
  cnt[t]++
}
BEGIN {
  split("4111111111111111 4242424242424242 4012888888881881 4000056655665556 5555555555554444 5105105105105100 2223003122003222 378282246310005 371449635398431 6011111111111117 3566002020360505 30569309025904", tc, " ")
  for (i in tc) testcard[tc[i]] = 1
  split("png jpg jpeg gif svg webp ico js mjs ts tsx jsx css scss map json lock", ex, " ")
  for (i in ex) fileext[ex[i]] = 1
}
{
  t = $1; ln = $2; v = $0; sub(/^[^:]*:[^:]*:/, "", v)
  if (t == "R") {
    sub(/^[^0-9]+/, "", v); sub(/[^0-9]+$/, "", v)
    d = onlydigits(v)
    if (rrn_ok(d)) { add("R", mask(v, 2), ln); rrn[d] = 1 }
  } else if (t == "P") {
    sub(/^[^0-9+]+/, "", v); sub(/[^0-9]+$/, "", v)
    d = onlydigits(v); if (substr(d, 1, 2) == "82") d = "0" substr(d, 3)
    rest = substr(d, 4)
    if (samedigits(rest) || rest == "12345678" || rest == "1234567" || rest == "87654321") next
    add("P", mask(v, (substr(v, 1, 1) == "+") ? 4 : 3), ln)
  } else if (t == "C") {
    sub(/^[^0-9]+/, "", v); sub(/[^0-9]+$/, "", v)
    d = onlydigits(v)
    if (length(d) < 13 || length(d) > 19) next
    if (d in rrn || rrn_ok(d)) next
    if (d in testcard || samedigits(d) || !card_range(d) || !luhn(d)) next
    add("C", mask(v, 4), ln)
  } else if (t == "E") {
    e = tolower(v); at = index(e, "@"); lp = substr(e, 1, at - 1); dom = substr(e, at + 1)
    tld = dom; sub(/^.*\./, "", tld)
    if (tld in fileext) next
    if (dom ~ /(^|\.)example\.(com|org|net)$/ || dom ~ /\.(example|invalid|test|localhost|local)$/ || dom == "localhost") next
    if (lp == "git" || lp == "noreply" || lp == "no-reply" || dom ~ /noreply\.github\.com$/) next
    if (e in seen) next
    seen[e] = 1
    add("E", substr(lp, 1, 1) "***@" substr(dom, 1, 1) "***", ln)
  }
}
END {
  for (t in cnt) {
    if (t == "E" && cnt[t] < emax) continue
    printf "%s\t%s\t%s\t%d\n", t, first[t], line[t], cnt[t]
  }
}'

# stdin 텍스트에서 PII 를 찾아 요약 줄을 출력한다. 표시 줄은 빈 줄로 바꿔 줄번호를 유지한다.
pii_scan() {
  local text
  text=$(awk -v m="$PII_MARKER" '{ if (index($0, m)) print ""; else print }')
  [ -n "$text" ] || return 0
  {
    printf '%s\n' "$text" | grep -Eno -e "$RRN_RE" 2>/dev/null | sed 's/^/R:/'
    printf '%s\n' "$text" | grep -Eno -e "$PHONE_RE" 2>/dev/null | sed 's/^/P:/'
    printf '%s\n' "$text" | grep -Eno -e "$CARD_RE" 2>/dev/null | sed 's/^/C:/'
    printf '%s\n' "$text" | grep -Eno -e "$EMAIL_RE" 2>/dev/null | sed 's/^/E:/'
  } | awk -F: -v chk="$RRN_CHECK" -v emax="$EMAIL_MAX" "$PII_AWK" | sort
}

# 요약 줄 -> 사람이 읽는 문구. $1 = 요약, $2 = 1 이면 줄번호 표시
pii_describe() {
  local out="" t m ln n label item
  while IFS="$(printf '\t')" read -r t m ln n; do
    [ -n "$t" ] || continue
    case "$t" in
      R) label="주민등록번호·외국인등록번호" ;;
      P) label="휴대폰 번호" ;;
      C) label="신용카드 번호" ;;
      E) label="이메일 주소 ${n}개" ;;
      *) continue ;;
    esac
    item="$label $m"
    [ "$t" = E ] && item="$label ($m 등)"
    [ "$t" != E ] && [ "$n" -gt 1 ] && item="$item 외 $((n - 1))건"
    [ "${2:-0}" = 1 ] && [ -n "$ln" ] && item="$item, ${ln}행"
    out="${out:+$out; }$item"
  done <<EOF
$1
EOF
  printf '%s' "$out"
}

HOW_TO_FIX="실제 개인정보라면 코드·저장소에 두지 말고 가짜 값이나 가명 데이터로 바꾸세요. 의도한 테스트 데이터라면 테스트 픽스처 경로(fixtures/, __fixtures__/, testdata/)에 두거나 해당 줄에 '${PII_MARKER}' 주석을 붙이세요."

path_allowed() {
  local p="/${1#/}" g
  case "$p" in
    */fixtures/*|*/__fixtures__/*|*/testdata/*) return 0 ;;
  esac
  set -f
  for g in ${CCG_PII_ALLOW_PATHS:-}; do
    # shellcheck disable=SC2254 # glob 으로 비교한다
    case "$1" in $g) set +f; return 0 ;; esac
    # shellcheck disable=SC2254
    case "$p" in $g) set +f; return 0 ;; esac
  done
  set +f
  return 1
}

check_write() {
  local path content found desc
  path=$(ccg_get '.tool_input.file_path // .tool_input.notebook_path')
  content=$(printf '%s' "$CCG_INPUT" | jq -r '
    [ .tool_input.content, .tool_input.new_string, .tool_input.new_source,
      ((.tool_input.edits // [])[]? | .new_string) ] | map(select(. != null)) | join("\n")' 2>/dev/null)
  [ -n "$content" ] || exit 0
  [ -n "$path" ] && path_allowed "$path" && exit 0
  found=$(printf '%s\n' "$content" | pii_scan)
  [ -n "$found" ] || exit 0
  if [ "$TOOL" = Write ]; then desc=$(pii_describe "$found" 1); else desc=$(pii_describe "$found" 0); fi
  ccg_deny "쓰려는 내용에 개인정보로 보이는 값이 있습니다: ${desc}. 파일: ${path##*/}. ${HOW_TO_FIX}"
}

# git 하위 명령과 -C 경로 파악 (secret-leak-guard 와 같은 방식)
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

# 저장소 기준 경로 목록(stdin)과 내용 공급 방식($1: cached|worktree|untracked)으로 검사
scan_files() {
  local mode=$1 f found
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    path_allowed "$f" && continue
    case "$mode" in
      cached) found=$(git -C "$TOP" diff --cached -- "$f" 2>/dev/null | grep -E '^\+' | grep -Ev '^\+\+\+ ' | sed 's/^+//' | pii_scan) ;;
      worktree) found=$(git -C "$TOP" diff -- "$f" 2>/dev/null | grep -E '^\+' | grep -Ev '^\+\+\+ ' | sed 's/^+//' | pii_scan) ;;
      untracked)
        [ -f "$TOP/$f" ] || continue
        [ "$(wc -c <"$TOP/$f" 2>/dev/null || echo 0)" -lt 1048576 ] || continue
        grep -Iq . "$TOP/$f" 2>/dev/null || continue
        found=$(pii_scan <"$TOP/$f") ;;
    esac
    if [ -n "$found" ]; then
      deny_msg="$(pii_describe "$found" 0) (파일: ${f##*/})"
      return 0
    fi
  done
}

check_git_add() {
  local i n w
  local -a specs
  specs=()
  n=${#CCG_W[@]}
  i=$((GIDX + 1))
  while [ "$i" -lt "$n" ]; do
    w=${CCG_W[$i]}
    case "$w" in
      -A|--all|.|-u|--update|:/) specs=(); break ;;
      --) ;;
      -*) ;;
      *) specs[${#specs[@]}]=$w ;;
    esac
    i=$((i + 1))
  done
  # 경로를 지정하지 않았거나 넓은 범위면 전체, 아니면 지정 경로만
  scan_files untracked <<EOF
$(git -C "$GDIR" ls-files --others --exclude-standard --full-name -- ${specs[@]+"${specs[@]}"} 2>/dev/null)
EOF
  [ -n "$deny_msg" ] && return 0
  scan_files worktree <<EOF
$(git -C "$GDIR" diff --name-only -- ${specs[@]+"${specs[@]}"} 2>/dev/null)
EOF
}

check_git_commit() {
  local all=0 w
  ccg_has_word -a --all -am && all=1
  for w in "${CCG_W[@]}"; do
    case "$w" in -[a-zA-Z]*a*) case "$w" in --*) ;; *) all=1 ;; esac ;; esac
  done
  scan_files cached <<EOF
$(git -C "$TOP" diff --cached --name-only 2>/dev/null)
EOF
  [ -n "$deny_msg" ] && return 0
  if [ "$all" = 1 ]; then
    scan_files worktree <<EOF
$(git -C "$TOP" diff --name-only 2>/dev/null)
EOF
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
    case "$GSUB" in add|commit) ;; *) continue ;; esac
    TOP=$(git -C "$GDIR" rev-parse --show-toplevel 2>/dev/null) || continue
    [ -n "$TOP" ] || continue
    case "$GSUB" in
      add) check_git_add ;;
      commit) check_git_commit ;;
    esac
    [ -n "$deny_msg" ] && ccg_deny "git ${GSUB} 대상 변경에 개인정보로 보이는 값이 있습니다: ${deny_msg}. ${HOW_TO_FIX}"
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
