# AIT-LDS v1.0 정규화·탐지 PoC

이 폴더는 AIT-LDS v1.0의 Apache access 로그와 Linux auth 로그를 정규화하고, Sigma 형식의 규칙을 적용해 **Detection Seed**를 생성한 뒤 라벨과 비교 평가하는 실행 가능한 PoC다. 탐지 결과는 최종 공격 판정이 아니라 이후 그룹화·조사·검증 단계가 사용할 후보 이벤트다.

## 범위와 로그 선택

| 로그 | 이번 주 우선순위 | 판단 근거 |
|---|---:|---|
| Apache access | P0, 구현·평가 완료 | Nikto 정찰, Hydra 로그인 시도, 웹셸 업로드, 웹셸 명령 실행이 한 로그에 나타나며 정상 트래픽과 함께 오탐을 측정할 수 있다. |
| auth.log | P0, 구현·평가 완료 | Dovecot 인증 실패를 독립적으로 확인할 수 있다. 단일 실패는 정상 사용자 실패와 구별되지 않아 낮은 심각도의 Seed로만 취급한다. |
| audit.log | P1, 다음 단계 | 권한 상승·프로세스·파일 행위의 호스트 증거에 적합하지만 이번 PoC의 웹/인증 탐지 범위를 넘는다. |
| Suricata eve.json | 보강 증거 | 이미 IDS 판정이 포함된 로그이므로 1차 규칙의 정답처럼 쓰면 평가 누수가 생긴다. 이후 교차 검증에 사용한다. |

데이터셋의 주요 공격 흐름은 정찰(Nmap/Nikto) → 계정 열거 → Hydra 인증 공격 → Horde 취약점 기반 웹셸 업로드 → 명령 실행/권한 상승이다. AIT-LDS 라벨 파일은 각 원본 로그와 줄 단위로 대응하며, 두 라벨 열을 모두 보존한다. 기본 평가는 이벤트 유사도·순서를 반영한 두 번째 열(`event`)을 사용하고 첫 번째 시간 구간 라벨(`time`)도 선택 가능하다. 라벨은 자동 생성되었고 수동 보정되지 않았으므로 오분류 가능성을 별도로 기록한다.

## 구현 구조

```text
3week/
├─ rules/                    # 실행 가능한 Sigma 형식 규칙 5개
├─ src/aitlds_detection/     # 정규화기, 라벨 정렬, 규칙 엔진, 지표, CLI
├─ tests/                    # 파서·규칙·라벨 정렬·공격/정상 테스트
├─ tools/                    # 공식 ZIP 선택 추출과 데이터 프로파일링
└─ reports/                  # 정규화 샘플, Detection Seed, 평가 결과
```

정규화 결과는 원문(`raw_line`), 파일·줄 번호, SHA-256 이벤트 ID, UTC 시각, 파서 버전·오류, 공통 필드를 보존한다. Apache는 `source.ip`, `http.request.*`, `url.*`, `http.response.*`, `user_agent.original`로, 인증 로그는 `event.action`, `event.outcome`, `auth.service`, `user.name`, `source.ip` 등으로 매핑한다. 정규화·라벨 결합·규칙 평가는 결정적이며 라벨은 탐지 조건에 들어가지 않는다.

규칙 엔진은 안전한 YAML 로딩, 필수 필드 검증, `logsource` 라우팅, 중첩 필드, `contains/startswith/endswith/all/exists/cased/neq`, 와일드카드, `and/or/not`, 괄호, `1 of/all of`를 지원한다. 이는 **명시적으로 제한한 Sigma 부분집합**이며 Sigma 전체 구현을 주장하지 않는다.

## 실행

Python 3.11 이상에서 다음과 같이 실행한다.

```powershell
python -m pip install -e .
$env:PYTHONPATH = "src"
python -m pytest -q
```

정규화 예시:

```powershell
python -m aitlds_detection.cli normalize `
  --log data/aitlds_sample/data/mail.cup.com/apache2/mail.cup.com-access.log `
  --log-type apache `
  --output reports/normalized_apache.jsonl
```

라벨 기반 평가 예시:

```powershell
python -m aitlds_detection.cli evaluate `
  --log data/aitlds_sample/data/mail.cup.com/apache2/mail.cup.com-access.log `
  --labels data/aitlds_sample/labels/mail.cup.com/apache2/mail.cup.com-access.log `
  --log-type apache `
  --rules rules `
  --output-dir reports/apache_event `
  --label-policy event
```

공식 3.25 GB ZIP 전체를 내려받지 않고 필요한 파일만 가져오는 도구도 포함한다.

```powershell
python tools/remote_zip.py `
  https://zenodo.org/api/records/3723083/files/AIT-LDS-v1_0.zip/content `
  extract --output-dir data/aitlds_sample `
  data/mail.cup.com/apache2/mail.cup.com-access.log `
  labels/mail.cup.com/apache2/mail.cup.com-access.log
```

## 결과와 해석

수치, 규칙별 결과, 오탐·미탐 원인 및 개선 우선순위는 [reports/RESULTS.md](reports/RESULTS.md)에 정리했다. 핵심은 Apache 규칙이 미사용 `mail.onion.com`에서 정상 75,565건에 오탐 0건, 공격 6,398건 중 6,397건 탐지라는 결과를 냈다는 점이다. 반면 auth 단일 이벤트 규칙은 공격 실패를 모두 찾지만 정상 로그인 실패 22건도 Seed로 만들었다. 따라서 인증 실패 Seed는 단독 경보가 아니라 시간 창 집계 및 웹 계층 Hydra Seed와의 상관분석 입력으로 사용해야 한다.

## 참고 자료

- [AIT-LDS v1.0 공식 데이터셋](https://zenodo.org/records/3723083)
- [Sigma Rule Specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)
- [Sigma Modifiers](https://sigmahq.io/sigma-specification/specification/sigma-appendix-modifiers.html)
- [Sigma Correlation Rules](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html)

