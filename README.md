# cc-guardrails-ko Lite (무료)

Claude Code 용 한국어 가드레일 훅 2종. 에이전트가 **개인정보와 시크릿**을 코드·문서·커밋에 넣는 순간을 도구 호출 직전에 멈춘다. 무료, MIT.

| 훅 | 막는 것 |
|---|---|
| `pii-leak-guard` | 주민등록번호·외국인등록번호(생년월일·성별 형식), 휴대폰 번호, 신용카드 번호(Luhn 확인), 한 번에 3개 이상의 이메일 주소가 든 파일 쓰기와 `git add`/`git commit` |
| `secret-leak-guard` | 토큰·개인 키가 든 파일 쓰기, `.env`·키 파일·토큰이 든 변경의 `git add`/`git commit`. 일반 `password = ...` 할당은 사용자 확인 |

차단되면 Claude 가 사유를 읽고 대개 스스로 고친다(값을 환경변수로 옮기거나 가짜 값으로 바꾼다). 차단 메시지에는 찾은 값을 가려서(`85****-*******`, `010-****-****`) 보여 주고 원문은 출력·저장하지 않는다.

## 요구 사항

macOS 또는 Linux, bash 3.2+, `jq`, `git`.

## 설치

압축을 푼 `lite/` 디렉토리에서:

```bash
mkdir -p ~/.claude/hooks/cc-guardrails-ko
cp -R hooks/* ~/.claude/hooks/cc-guardrails-ko/
chmod +x ~/.claude/hooks/cc-guardrails-ko/*.sh
```

`settings.example.json` 의 `hooks` 항목을 `~/.claude/settings.json` 에 합친다. 이미 `hooks` 가 있으면 이벤트별 배열에 항목을 추가한다. 특정 프로젝트에만 쓰려면 `<프로젝트>/.claude/settings.json` 에 넣는다.

확인: Claude Code 에서 `/hooks` 로 등록을 보고, "`src/demo.ts` 에 `const key = 'AKIA` 로 시작하는 가짜 AWS 키 넣어 줘"처럼 요청해 차단되는지 본다. 경로가 틀리면 Claude Code 는 오류 알림만 띄우고 진행하므로 한 번은 꼭 확인한다.

## 개인정보 가드의 예외

가짜 테스트 데이터가 막히면 둘 중 하나를 쓴다.

1. **테스트 픽스처 경로**: 경로에 `fixtures/`, `__fixtures__/`, `testdata/` 디렉토리가 들어가면 검사하지 않는다 (glob `*/fixtures/*`, `*/__fixtures__/*`, `*/testdata/*`). 경로 추가는 `CCG_PII_ALLOW_PATHS`.
2. **줄 단위 표시**: 같은 줄에 `pii-guard: allow` 주석이 있으면 그 줄만 검사하지 않는다.
   ```ts
   const SAMPLE_PHONE = "010-9876-5432"; // pii-guard: allow
   ```

예외는 가짜 값에만 쓴다. 계좌번호·여권번호·이름·주소는 형식만으로 구별이 어려워 검사하지 않는다.

## 설정

settings.json 의 `env` 로 조정한다.

- `CCG_DISABLE="pii-leak-guard"` — 훅 끄기 (쉼표 구분)
- `CCG_PII_EMAIL_THRESHOLD=3` — 이메일 차단 기준 개수
- `CCG_PII_ALLOW_PATHS="*/seed/* docs/samples/*"` — 개인정보 가드 예외 경로 (공백 구분 glob)
- `CCG_PII_RRN_CHECKSUM=1` — 주민등록번호 검증번호까지 확인해 오탐을 줄임. 기본값(0)은 날짜 형식만 본다 — 2020년 10월 이후 발급 번호는 검증번호 공식이 맞지 않아, 켜면 그 번호를 놓친다
- `CCG_FAIL_CLOSED=1` — jq 없음 등 내부 오류 시에도 차단 (기본은 비차단 + 오류 표시)

## 한계

형식과 검증번호로 판별하므로 형식이 없는 개인정보(이름·주소)는 보지 못한다. 이미 커밋된 기록, 바이너리·압축·엑셀 파일 내용도 보지 않는다. 셸 문법을 완전히 해석하지 않으며, 악의적 우회를 막는 보안 도구가 아니다. 저장소 전체 검사는 gitleaks 같은 전용 도구를 함께 쓴다.

## 라이선스

MIT. `LICENSE` 참고.

---

## Pro 버전 (29,000원)

Lite 는 단독으로 쓸 수 있다. Pro 는 Lite 2종에 운영 사고 방지 훅 6종과 규칙·해설서·설치기를 더한다.

| | Lite (무료) | Pro (29,000원) |
|---|---|---|
| 개인정보 유출 가드 (주민·외국인등록번호, 휴대폰, 카드, 이메일 대량) | O | O |
| 시크릿 유출 가드 (토큰·개인 키, `.env` 커밋) | O | O |
| 배포 대상 명시 가드 (`firebase --project`, `kubectl --context`, `aws --profile` 등 누락 차단) | - | O |
| 파괴적 명령 가드 (넓은 `rm -rf`, main 강제 push, 변경 있는 `reset --hard`, SQL DROP 확인) | - | O |
| 블로킹 감시 경고 (`gh run watch`, `tail -f` 등) | - | O |
| 가드 우회 차단 (`--no-verify`, 훅 끄기, 훅 파일 수정) | - | O |
| 검증 없는 완료 선언 방지 (편집 후 테스트 없이 "완료" 시 계속 진행 요구) | - | O |
| 실행 떠넘기기 경고 (이유 없이 사용자에게 명령 실행 요청) | - | O |
| CLAUDE.md 규칙 조각 8편 | - | O |
| 설치·제거 스크립트 (설정 자동 병합, 백업, 재설치 중복 없음) | 수동 설치 | O |
| 한국어 해설서 (실패 유형 · 규칙 · 훅 동작 · 한계, 13장 + 부록) | - | O |
| 테스트 스위트 | - | O |
| 1.x 업데이트 | O | O (무료) |

Pro 에 대한 설명과 구매 링크는 저장소 상단 소개를 본다. 구매 후 다운로드 전에는 7일 이내 전액 환불된다.
