# 비용 제약을 고려한 Windows 포렌식의 다음 증거 조회 선택

Evaluating Budgeted Evidence Selection for Windows Forensic Investigations

## 요 약

Windows 포렌식에서 어떤 자료를 먼저 조회할지는 남은 조사 비용과 그 자료로 구분할 수 있는 가설에 달려 있다. 본 연구는 동일한 증거가 서로 다른 판단으로 이어질 수 있는 상황을 가설과 예상 조회 결과로 표현하고, 남은 예산에서 판정 가능한 가설의 수를 가장 크게 만드는 조회 순서를 계산했다. 이 방법을 Forensic-Claw의 다음 증거 추천 명령으로 구현했다. Windows의 Microsoft Edge에서 독립 프로필을 사용해 파일 다운로드 24건을 실행하고, 그중 후속 수집분 16건을 평가했다. 기본 비용 조건에서 예산이 3일 때 제안 방식은 16건을 판정했고, 한 단계씩 선택하는 탐욕 방식은 12건을 판정했다. 개발 자료에서 최적화한 고정 순서도 이 조건에서는 16건을 판정했다. 프로필별 기록 조회가 분리된 조건에서는 제안 방식과 탐욕 방식이 각각 16건을, 최적 고정 순서는 8건을 판정했다. 결과는 자료 접근 경로가 분기하는지와 비용 구조에 따라 적응적 선택의 이점이 달라짐을 보여준다.

**주제어** 디지털 포렌식, 증거 선택, 제한 예산, 가설 검증, 브라우저 기록

## Abstract

Choosing the next source to examine in a Windows forensic investigation depends on the remaining budget and the hypotheses that the source can distinguish. We implement a budgeted evidence planner in Forensic-Claw. It maximizes the number of modeled hypotheses whose verdict can be determined and breaks ties by minimizing total query cost. We captured 24 controlled Microsoft Edge downloads on Windows and used 16 independently collected traces for replay evaluation. At a budget of three units under the standard cost schedule, the planner resolved 16 of 16 trials, compared with 12 for a greedy policy and 16 for a fixed order tuned on the development batch. With profile-specific archives, the planner and the greedy policy each resolved 16 trials, while the tuned fixed order resolved eight. These findings identify conditions under which adaptive selection helps and conditions under which a fixed order is sufficient.

**Keywords** digital forensics, evidence selection, budgeted planning, hypothesis testing, browser history

## Ⅰ. 서론

서로 다른 출처에서 동일한 파일을 내려받으면 파일의 SHA-256은 같다. 조사 대상이 파일의 내용이라면 이 해시는 유용하다. 그러나 최종 다운로드 출처를 조사하는 상황에서는 다른 자료가 필요하다. 브라우저 프로필을 먼저 확인하면 조사 대상이 아님을 바로 판정할 수도 있다. 프로필이 일치하면 해당 다운로드 행의 URL 체인이나 서버 측 기록까지 확인해야 한다. 이때 필요한 자료는 앞선 조회 결과에 따라 달라진다.

Forensic-Claw에 추가한 다음 증거 추천 기능은 현재 관측과 양립하는 가설을 찾아, 각 후보 자료가 판정에 어떤 차이를 만드는지 계산한다. 본 연구는 같은 증거 목록과 판단 규칙을 공유하는 비교 방식들에 비용을 동일하게 적용했다. 연구 질문은 **적응적 조회가 어떤 비용과 자료 접근 구조에서 고정 순서보다 많은 사건을 판정하며, 한 단계씩 선택하는 방법은 언제 충분한가**이다.

## Ⅱ. 관련 연구

Nisioti 등의 DISCLOSE는 이전 사건에서 추정한 공격 행위의 관계와 검사 비용을 바탕으로, 제한 예산에서 확인한 공격 행위의 편익을 최대화한다[1]. 본 연구에서는 확인한 활동 수 대신 명제의 지지·반증이 가능한 실행 수를 평가하고, 프로필별로 조회가 갈리는 경우와 고정 순서로도 충분한 경우를 함께 비교했다. 기존에는 수집 방식의 침습성을 기준으로 확보 순서를 정하는 연구도 있었다[2]. Windows 포렌식의 CAFE는 이질적인 아티팩트를 주장 단위로 교차 검증한다[3]. 본 연구는 브라우저의 구체적인 판단 하나에 대해 조회 결과의 분기에 따라 선택 순서가 바뀌는 경우를 조사한다.

가설을 구분하기 위한 비용 민감 검사 선택은 능동학습과 의사결정트리의 연구 주제다[4]. 본 연구는 유한 예산의 판정 문제에 이 틀을 적용한다. 같은 판정을 내리는 여러 가설을 끝까지 식별할 필요는 없다. 예산이 부족하면 보류할 수 있으며, 모형과 양립하는 가설이 없으면 불일치로 남긴다. NIST의 포렌식 검토가 설명하듯, 수집된 아티팩트의 의미와 관측 범위를 이해해야 판단 근거를 해석할 수 있다[5].

## Ⅲ. 방법

### 3.1 판정과 조회 순서

사건 모형에는 가설별 판정, 조회 항목, 각 조회의 양의 정수 비용, 가설별 예상 결과를 등록한다. 가설의 예상 결과와 이미 관측한 값이 다르면 후보에서 제거한다. 남은 가설이 모두 같은 판정을 가지면 지지 또는 반증을 반환한다. 다른 판정의 가설이 함께 남아 있으면 보류하고, 어느 가설과도 맞지 않으면 불일치를 반환한다.

추천기는 예산 안에서 가능한 조회를 하나씩 고려한다. 각 조회가 낼 수 있는 결과별로 가설 집합을 나누고, 남은 예산으로 같은 계산을 반복한다. 분기 끝에서 판정할 수 있는 가설 수를 합산해 가장 큰 쪽을 선택한다. 동률이면 판정에 이르지 못한 분기를 포함해 전체 가설에서 발생하는 총 조회 비용이 작은 쪽을 택한다. 이미 조회한 항목은 다시 선택하지 않는다. 모든 가설에 동일한 가중치를 적용했다. 계산은 동일한 가설 집합, 남은 조회, 예산으로 돌아왔을 때 이전 결과를 재사용한다.

CLI 명령은 사건 모형 JSON과 이미 확인한 결과를 받아 현재 판정, 남은 가설, 다음 조회, 예상 결과별 즉시 판정을 출력한다. 예를 들어 프로필 조회가 다른 프로필을 반환하면 첫 명제는 반증 상태가 되고, 대상 프로필이면 추가 조회가 필요하다고 표시한다. 조회 실행과 원본 접근은 분석가가 맡는다. 구현은 최대 조회 항목 10개와 가설 32개인 모형을 받는다.

### 3.2 Windows 기록 수집

Windows 11의 Edge 158.0.4370.33에서 Playwright CLI 0.1.25를 사용했다. 각 회차에 대상·대조 프로필을 새로 만들고 파일을 8회 내려받았다. 로컬 HTTP 서버의 시작 URL, 중간 리디렉션, 최종 파일 응답을 거치게 했으며, 최종 응답 서버 두 곳은 같은 바이트를 제공했다. 세 회차에서 24개 다운로드를 확보했다. 브라우저를 닫고 History SQLite의 downloads 및 downloads_url_chains를 읽기 전용으로 조회했다. 완료 상태, URL 순서, 내려받은 파일의 해시, 서버가 기록한 응답 출처를 확인했다.

첫 회차 8건은 고정 순서 선택에 쓰고, 나머지 두 회차 16건은 평가에만 사용했다. 실행마다 새 프로필과 HTTP 세션을 사용했으나, 두 평가 회차는 개발 회차의 여덟 실험 조건을 반복한 것이다. 결과는 독립적인 실제 수사 사건 16건의 일반화 성능으로 해석할 수 없다.

### 3.3 평가 조건과 기준선

세 비용표에서 판단 대상은 “대상 프로필에서 최종 출처 A로 내려받았는가”이다. 각 실행의 프로필과 실제 HTTP 응답 출처를 정답으로 사용했다. 기본 비용은 파일 해시 1, 전체 History 조회 4, 중간 경로 확인 1, 프로필 확인 1, 최종 URL 연결 2, 서버 기록 조회 3으로 두었다. 두 민감도 조건에서는 전체 History 비용을 2로 내리거나, 최종 URL 비용을 4로 올리고 서버 조회 비용을 2로 낮췄다. 서버 기록을 활용할 수 없는 경우도 재생 조건에 포함했다.

프로필별 분리 조건은 “대상 프로필은 A, 대조 프로필은 B라는 지정 출처에서 내려받았는가”를 판단한다. 해당 프로필의 아카이브에서만 URL을 조회할 수 있다고 가정했다. 프로필 확인 비용은 1, 두 아카이브 조회는 각각 2이다. 이 조건은 같은 실제 브라우저 기록을 재사용하며, 별도 운영 환경에서 수집한 결과가 아니다. 비용은 실제 소요 시간이 아닌 가정한 조회 단위다.

네 비교 방식은 체크리스트 순서, 개발 자료에서 모든 순열을 비교해 고른 고정 순서, 반대 판정의 가설 쌍을 비용 대비 가장 많이 분리하는 탐욕 선택, 유한 예산에서 여러 단계를 탐색하는 제안 방식이다. 고정 순서는 남은 예산으로 실행할 수 있는 첫 미조회 항목을 선택한다. 모든 방식의 최종 판정은 같은 후보 가설 필터를 사용한다. 주 지표는 정답 판정 건수이며, 보류, 오판, 총 조회 비용도 기록했다. 예산 1–5와 네 비용·접근 조건을 적용해 1,280건의 정책 재생을 수행했다.

## Ⅳ. 결과

**표 1. 예산 3에서의 정답 건수와 평가 16건 전체의 조회 비용**

| 조건 | 체크리스트 | 최적 고정 순서 | 탐욕 | 제안 |
|---|---:|---:|---:|---:|
| 기본 | 12/16 · 42 | 16/16 · 32 | 12/16 · 26 | 16/16 · 32 |
| 전체 History 비용 감소 | 16/16 · 48 | 16/16 · 32 | 16/16 · 32 | 16/16 · 32 |
| 최종 URL 비용 증가 | 12/16 · 42 | 16/16 · 32 | 12/16 · 26 | 16/16 · 32 |
| 프로필별 아카이브 | 0/16 · 32 | 8/16 · 40 | 16/16 · 48 | 16/16 · 48 |

기본 비용에서는 프로필을 먼저 확인하는 정책이 대상이 아닌 절반의 시험을 비용 1에서 판정했다. 대상 프로필이면 비용 2인 최종 출처 확인으로 나머지 시험을 판정했다. 최적 고정 순서도 이 순서를 선택할 수 있어 제안 방식과 같았다. 탐욕 방식은 예산 3에서 4건을 더 보류했고 예산 4에서는 전체를 판정했다. 예산 4에서 전체 판정 비용은 탐욕 방식 34, 제안 방식 32였다.

프로필별 아카이브를 분리하면, 예산 3으로 프로필 확인 뒤 접근할 아카이브 하나를 골라야 한다. 고정 순서는 프로필 조회 결과에 따라 두 아카이브의 상대 순서를 바꿀 수 없어 8건을 판정했다. 탐욕과 제안 방식은 다른 프로필에서 서로 다른 아카이브를 선택해 16건을 판정했다. 전체 History를 낮은 비용으로 볼 수 있는 설정에서는 예산 3의 최적 고정 순서, 탐욕, 제안 방식이 동일한 정답 건수와 총 비용을 보였다.

실험에서 오판은 기록되지 않았다. 관측 결과의 출처가 알려진 통제 자료에서, 네 방식이 관측과 양립하는 가설의 판정이 일치할 때만 결론을 내린 결과다. 오판 0건을 실제 사건의 오류율로 해석할 수 없다. 그림 1은 예산에 따라 결과의 차이가 발생하거나 사라지는 지점을 보여준다.

@FIG budget-curves.png
**<Fig. 1> 기본 및 프로필별 아카이브 조건에서 예산별 정답 판정 건수**

### 4.1 Pi 모델이 작성한 조회 순서

두 조건에서 자체 호스팅 모델 nvidia/Qwen3.8-Flash-Next-NVFP4-QAD[6]에 Pi를 통해 가설·결과표와 예산 3을 제시하고 조건부 조회 순서를 한 번씩 요청했다. Pi의 추론 설정은 low였다. 모델에는 평가 실행의 실제 결과를 제공하지 않았다. 프로필별 아카이브 조건에서 모델이 반환한 정책은 16/16건을 총 비용 48에 판정했다. 기본 조건의 응답에는 설명과 JSON 코드 블록이 같이 있어 JSON 전용 출력 기준에 걸렸다. 코드 블록에 든 정책을 그대로 재생하는 별도 분석에서는 16/16건을 총 비용 32에 판정했다. 두 조건에서 얻은 정책은 제안 방식과 같은 판정 및 비용을 보였다. 이 비교는 두 번의 요청에 대한 기술적 관찰이며, 모델 안정성에 대한 반복 측정은 아니다.

## Ⅴ. 고찰

일반적으로 앞을 더 멀리 탐색한다고 해서 실무 판정이 크게 나아지는 것은 아니다. 이 실험에서는 두 가지 이점이 다른 조건에서 나타났다. 기본 조건에서 제안 방식은 한 번 뒤의 조회 비용까지 고려해 탐욕 방식보다 예산 3에서 더 많이 판정했다. 프로필별 아카이브 조건에서는 조회 결과에 따라 갈라지는 능력이 고정 순서와의 차이를 만들었으며, 그 경우에는 탐욕 선택으로도 충분했다. 전체 기록의 확인 비용이 낮아지면 계산이 복잡한 정책의 이점도 작아졌다.

분석가가 가설의 범위와 조회 결과를 사전에 정의하는 데 드는 시간은 포함하지 않았다. 특히 모형 밖의 사건이 모형 내 가설과 같은 관측을 만들 수 있다. 불일치 상태는 모든 등록 가설과 관측이 어긋날 때만 발생한다. 설정에 없는 가설을 자동으로 감지하거나 사건의 진실을 보장하는 기능은 평가하지 않았다. 다른 브라우저 버전, 현장 자료, 원본이 누락된 사건, 시간 실측과 조사관의 검토 시간은 별도 평가가 필요하다.

## Ⅵ. 결론

Forensic-Claw에 남은 비용과 가설을 입력하면 다음 조회를 추천하는 기능을 구현했다. Windows 브라우저 기록을 재생한 비교에서 전체 자료를 저렴하게 조회할 수 있는 조건은 고정 순서로도 해결할 수 있었다. 확인할 위치가 앞선 관측에 따라 달라지는 조건에서는 적응적 조회가 같은 예산에서 더 많은 판단을 내렸다. 다음 조사 항목의 가치는 아티팩트의 이름뿐 아니라, 해당 항목이 남은 가설을 어떻게 구분하며 어떤 비용으로 접근 가능한지에 따라 달라졌다.

## 참고문헌

[1] A. Nisioti et al., “Data-Driven Decision Support for Optimizing Cyber Forensic Investigations,” IEEE Transactions on Information Forensics and Security. https://aronlaszka.com/papers/nisioti2021data.pdf

[2] G. Horsman, 2022, “An order of data acquisition for digital forensic investigations,” Journal of Forensic Sciences. https://doi.org/10.1111/1556-4029.14979

[3] H. Shin and J. Park, “CAFE: A Claim-Level Cross-Artifact Verification Framework for Assessing the Reliability of Windows Forensic Evidence under Anti-Forensic Manipulation,” DFRWS presentation. https://dfrws.org/presentation/cafe-a-claim-level-cross-artifact-verification-framework-for-assessing-the-reliability-of-windows-forensic-evidence-under-anti-forensic-manipulation/

[4] D. Golovin, A. Krause, and D. Ray, 2010, “Near-Optimal Bayesian Active Learning with Noisy Observations,” NeurIPS. https://arxiv.org/abs/1010.3091

[5] J. Lyle et al., 2022, “Digital Investigation Techniques: A NIST Scientific Foundation Review,” NISTIR 8354. https://doi.org/10.6028/NIST.IR.8354

[6] NVIDIA, “Qwen3.8-Flash-Next-NVFP4-QAD,” model card. https://huggingface.co/nvidia/Qwen3.8-Flash-Next-NVFP4-QAD
