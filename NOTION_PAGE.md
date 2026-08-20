<callout icon="✅" color="green_bg">
	**완료:** AIT-LDS v1.0의 Apache access와 auth.log를 대상으로 정규화기, 제한된 Sigma matcher, 규칙 5개, 라벨 기반 평가기를 구현했다. 최종 미사용 테스트베드에서 웹 로그 정상 75,565건의 오탐은 0건이었고 공격 라벨 6,398건 중 6,397건을 탐지했다. 남은 1건은 공격 행위가 아닌 Apache 내부 더미 연결에 붙은 라벨이다.
</callout>

## 0. 범위와 참고 자료

- 시스템 관측 계층과 로그 구성: [Agentic SOC 아키텍처 초안](https://app.notion.com/p/3bf3d902efd481f29bd6c5f3f74a4ba4)
- Detection Seed 중심 파이프라인: [AI Agentic SOC v2](https://app.notion.com/p/AI-Agentic-SOC-v2-3c0770e4c47980398d05d5b05e4a0d84)
- 실행 계획: <mention-page url="https://app.notion.com/p/3c278753a4b0801dbbdbe3353f7548e7">1차 탐지 개발 — 주간 실행 계획</mention-page>
- 공식 데이터: [AIT-LDS v1.0](https://zenodo.org/records/3723083)
- 공식 문법: [Sigma Rule Specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html), [Modifiers](https://sigmahq.io/sigma-specification/specification/sigma-appendix-modifiers.html), [Correlation](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html)

이번 구현에서 Sigma 매치는 공격 확정이 아니라 후속 사건 묶기·조사·Validator가 사용할 **Detection Seed**다. Ground Truth 라벨은 평가에만 사용하며 탐지 조건에는 넣지 않았다.

## 1. AIT-LDS 로그 확인 및 공격·정상 구분

AIT-LDS v1.0은 독립 테스트베드 4개에서 6일 동안 정상 활동을 생성하고 공격일에 공격 체인을 실행한 데이터셋이다. 이번 구현에서 확인한 공격 흐름은 다음과 같다.

1. Nmap/Nikto 정찰
2. SMTP 사용자 열거
3. Hydra 인증 공격
4. Horde 취약점을 이용한 웹셸 업로드
5. 웹셸 명령 실행 및 후속 권한 상승

라벨 파일은 원본 로그와 줄 단위로 정렬되어 있으며 한 줄에 라벨 두 개가 있다.

- 첫 번째 열: 공격 발생 시간 구간 중심 라벨
- 두 번째 열: 이벤트 유사도와 순서를 반영한 라벨
- 기본 평가 정책: 두 번째 열 `event`
- 두 열을 모두 정규화 결과에 보존하고 `--label-policy event|time`으로 선택 가능
- 라벨은 자동 생성되었고 수동 보정되지 않았으므로 시간 구간에 섞인 정상 이벤트가 공격으로 표시될 수 있음

개발 서버 `mail.cup.com`의 이벤트 라벨 분포는 다음과 같다.

<table fit-page-width="true" header-row="true">
	<tr>
		<td>로그</td>
		<td>전체</td>
		<td>정상</td>
		<td>공격 라벨</td>
	</tr>
	<tr>
		<td>Apache access</td>
		<td>148,534</td>
		<td>141,903</td>
		<td>Nikto 6,295 / Hydra 329 / upload 5 / webshell-id 1 / mail-curl 1</td>
	</tr>
	<tr>
		<td>auth.log</td>
		<td>1,224</td>
		<td>938</td>
		<td>Hydra 286</td>
	</tr>
</table>

공격·정상 구분은 “문자열이 수상해 보이는가”가 아니라 라벨과 원본 행위를 함께 확인했다. 예를 들어 Hydra 구간에 들어간 `::1 OPTIONS *` Apache 내부 더미 연결은 공격 라벨이지만 공격자 행위가 아니므로 규칙에 포함하지 않았다. 반대로 auth.log의 정상 사용자 인증 실패는 실제 실패 이벤트이므로 단일 이벤트만으로 Hydra라고 확정할 수 없다.

## 2. 어떤 로그를 잡을지 결정

<table fit-page-width="true" header-row="true">
	<tr>
		<td>로그</td>
		<td>결정</td>
		<td>근거</td>
	</tr>
	<tr>
		<td>Apache access</td>
		<td>**P0, 구현 완료**</td>
		<td>Nikto, Hydra, 웹셸 업로드, 웹셸 명령 실행을 정상 웹 트래픽과 함께 평가 가능</td>
	</tr>
	<tr>
		<td>auth.log</td>
		<td>**P0, 구현 완료**</td>
		<td>Dovecot 인증 실패라는 독립 인증 계층 증거 제공. 정상 실패와 겹치므로 낮은 심각도 Seed로 사용</td>
	</tr>
	<tr>
		<td>audit.log</td>
		<td>P1</td>
		<td>프로세스·파일·권한 상승 증거에 적합. 이번 웹/인증 PoC 이후 호스트 계층 확장 대상으로 둠</td>
	</tr>
	<tr>
		<td>Suricata eve.json</td>
		<td>보강 증거</td>
		<td>이미 IDS alert가 들어 있으므로 주 탐지 입력에 쓰면 정답 누수와 성능 과대평가 가능</td>
	</tr>
</table>

따라서 이번 주 최소 두 계층은 Apache access + auth.log로 확정했다. 웹 계층에서는 구체적인 공격 행위를 정밀하게 잡고, 인증 계층에서는 폭넓은 실패 Seed를 만든 뒤 다음 단계에서 시간 창과 웹 Seed를 연결하는 구조다.

## 3. 정규화 설계와 구현

정규화기는 결정론적으로 동작하며 다음 정보를 보존한다.

- 원본 로그 전체 `raw_line`
- 원본 파일과 줄 번호
- 파일·줄·원문 기반 SHA-256 `event_id`
- UTC ISO-8601 시각
- 파서 이름·버전·성공 여부·오류 목록
- Apache: source IP, method, path/query, status, bytes, referrer, User-Agent
- auth: host, process, action/outcome, auth service, user, source IP
- 두 Ground Truth 라벨과 실제 평가 정책

Apache combined 형식의 escaped quote와 요청이 `-`인 timeout 행까지 처리하고, auth syslog의 연도 누락은 실행 인자로 명시한다. 파싱 실패를 버리지 않고 오류와 원문을 남긴다. 세 테스트베드의 이번 평가 파일에서 파싱 실패는 0건이었다.

구현 위치: `D:\WHs\오관완\3week\src\aitlds_detection`

## 4. Sigma 구조 이해 및 공격 규칙

Sigma 룰은 크게 메타데이터, `logsource`, `detection`, `falsepositives`, `level`, `tags`로 구성된다. `detection` 안의 selection은 필드 조건을 정의하고 `condition`이 selection들을 `and`, `or`, `not`, 괄호 등으로 조합한다. 이번 matcher는 안전한 YAML 로드와 필수 필드 검증 후 다음 부분집합만 명시적으로 지원한다.

- 중첩 필드 조회와 logsource 라우팅
- `contains`, `startswith`, `endswith`, `all`, `exists`, `cased`, `neq`
- 와일드카드 비교
- `and`, `or`, `not`, 괄호, `1 of`, `all of`
- 알 수 없는 modifier/selection/중복 ID는 로딩 실패
- Python `eval`을 쓰지 않는 재귀 조건 파서

이는 Sigma 전체 호환 엔진이 아니라 이번 PoC에 필요한 **Sigma subset**이다.

<table fit-page-width="true" header-row="true">
	<tr>
		<td>규칙</td>
		<td>핵심 조건</td>
		<td>대상</td>
	</tr>
	<tr>
		<td>Apache Nikto Scanner Activity</td>
		<td>User-Agent의 `Nikto/` 또는 HTTP 400 + 빈 User-Agent</td>
		<td>Nikto 정찰</td>
	</tr>
	<tr>
		<td>Apache Hydra Login Client</td>
		<td>`/login.php` + Hydra User-Agent</td>
		<td>웹 로그인 brute force</td>
	</tr>
	<tr>
		<td>Automated Horde Webshell Upload Sequence</td>
		<td>python-requests + login/turba/evil.php 경로</td>
		<td>웹셸 업로드 자동화</td>
	</tr>
	<tr>
		<td>Webshell Command in HTTP Query</td>
		<td>`/static/evil.php` + query의 `cmd=`</td>
		<td>웹셸 명령 실행</td>
	</tr>
	<tr>
		<td>Dovecot Authentication Failure</td>
		<td>Dovecot + authentication failure</td>
		<td>인증 실패 Seed, 단독 공격 확정 금지</td>
	</tr>
</table>

각 Detection Seed에는 룰 ID·해시 버전·매치 selection·마스킹된 필드·원본 파일과 줄 번호가 들어간다.

## 5. 스크립트 적용과 재현 방법

로컬 산출물 루트: `D:\WHs\오관완\3week`

- `README.md`: 범위, 구조, 설치·실행 명령
- `rules/`: 실행 규칙 5개
- `src/aitlds_detection/normalizers.py`: Apache/auth 정규화기
- `src/aitlds_detection/rule_engine.py`: Sigma subset matcher
- `src/aitlds_detection/cli.py`: normalize/evaluate 실행기
- `reports/`: 정규화 샘플, Detection Seed, 룰 manifest, 지표
- `reports/RESULTS.md`: 전체 성능과 오류 분석
- `tests/`: 공격·정상·경계·라벨 정렬·잘못된 룰 테스트

```powershell
cd D:\WHs\오관완\3week
python -m pip install -e .
$env:PYTHONPATH = "src"
python -m pytest -q
python -m aitlds_detection.cli evaluate --log data\aitlds_sample\data\mail.onion.com\apache2\mail.onion.com-access.log --labels data\aitlds_sample\labels\mail.onion.com\apache2\mail.onion.com-access.log --log-type apache --rules rules --output-dir reports\holdout_onion_apache --label-policy event
```

공식 3.25 GB ZIP은 전체 다운로드하지 않고 HTTP range로 중앙 디렉터리를 읽어 필요한 로그만 선택 추출하는 `tools/remote_zip.py`를 구현했다.

## 6. 공격 탐지·정상 오탐 시험

데이터 누수를 줄이기 위해 서버를 다음과 같이 분리했다.

- 개발: `mail.cup.com`
- 규칙 일반화: `mail.insect.com`
- 최종 미사용 검증: `mail.onion.com`

최초 Nikto 규칙은 개발 데이터의 `HTTP 400 + 빈 User-Agent`에 과적합되어 insect 서버에서 6,296건 중 81건만 잡았다. 이를 명시적 Nikto 식별자 또는 고유한 비정상 조합으로 일반화했고, insect는 개선 데이터로만 기록했다. 이후 규칙을 더 바꾸지 않고 onion 서버를 최종 평가했다.

### 최종 Apache 결과 — mail.onion.com

<table fit-page-width="true" header-row="true">
	<tr>
		<td>전체</td>
		<td>TP</td>
		<td>FP</td>
		<td>FN</td>
		<td>TN</td>
		<td>Precision</td>
		<td>Recall</td>
		<td>F1</td>
	</tr>
	<tr>
		<td>81,963</td>
		<td>6,397</td>
		<td>0</td>
		<td>1</td>
		<td>75,565</td>
		<td>1.000000</td>
		<td>0.999844</td>
		<td>0.999922</td>
	</tr>
</table>

- 정상 75,565건에서 오탐 0건
- Nikto 6,295 / upload 5 / webshell command 1 모두 탐지
- Hydra 실제 요청 96건 모두 탐지
- FN 1건은 `::1 OPTIONS *` 내부 더미 연결에 Hydra 라벨이 붙은 사례로 공격 행위가 아님

### 최종 auth 결과 — mail.onion.com

<table fit-page-width="true" header-row="true">
	<tr>
		<td>전체</td>
		<td>TP</td>
		<td>FP</td>
		<td>FN</td>
		<td>TN</td>
		<td>Precision</td>
		<td>Recall</td>
		<td>F1</td>
	</tr>
	<tr>
		<td>1,050</td>
		<td>94</td>
		<td>22</td>
		<td>0</td>
		<td>934</td>
		<td>0.810345</td>
		<td>1.000000</td>
		<td>0.895238</td>
	</tr>
</table>

auth 오탐 22건은 정상 사용자의 실제 Dovecot 인증 실패다. 이 결과는 코드 오류가 아니라 단일 이벤트 조건의 정보 부족을 보여준다. 따라서 규칙 심각도를 `low`로 두고 다음과 같이 보완한다.

1. 같은 사용자·출발지의 실패를 1분 시간 창으로 집계하는 Sigma `event_count` correlation
2. Apache Hydra Seed와 계정·시간을 연결
3. 정상 사용자 실패 패턴과 승인된 테스트를 예외 정책으로 분리
4. correlation 전에는 auth Seed 단독으로 고심각도 경보를 생성하지 않음

### 자동화 시험

- **11개 테스트 통과**
- 정규화 positive/edge case
- 정상 웹 요청 non-match
- Nikto 응답 코드 변화 회귀 테스트
- 웹셸 공격 match와 원본 줄 역추적
- condition parser와 잘못된 selection 거부
- 라벨 행 수 불일치 거부

## 7. 결론과 다음 작업

<callout icon="📌" color="blue_bg">
	웹 계층 규칙은 최종 미사용 데이터에서 정상 오탐 없이 공격 행위를 탐지했다. 인증 계층은 공격을 모두 포착하지만 정상 실패도 함께 잡으므로 “낮은 심각도의 Seed → 시간 창 그룹화 → 웹 Seed와 상관분석”으로 사용해야 논리적으로 타당하다.
</callout>

- [x] AIT-LDS 공격·정상 라벨 및 라벨 정책 확인
- [x] Apache + auth 두 로그 선정
- [x] 결정론 정규화기 2종 구현
- [x] Sigma subset matcher와 규칙 5개 구현
- [x] Detection Seed 원본 행 역추적
- [x] 개발/개선/최종 미사용 데이터 분리
- [x] TP·FP·FN·TN, Precision·Recall·F1·FPR 생성
- [x] 정상·공격 자동 시험 11개 통과
- [ ] 인증 실패 Sigma correlation 구현
- [ ] auditd 호스트 증거 및 Suricata 교차 검증 추가
- [ ] 운영 정상 로그와 추가 테스트베드로 외부 타당성 검증

