# LLM 기반 Windows 포렌식에서 어떤 증거를 먼저 조회해야 하는가

Evaluating Evidence Query Order for LLM-Assisted Windows Forensics

## 요 약

서로 다른 URL에서 받은 파일의 바이트가 같으면 SHA-256 값도 같다. 파일 해시만으로는 해당 다운로드의 최종 URL을 식별할 수 없다. 브라우저 프로필이나 최종 URL을 추가로 확인해야 하는데, 어떤 자료를 먼저 조회하느냐에 따라 같은 예산으로 내릴 수 있는 판단이 달라진다. 본 연구는 이 문제를 다루기 위해, 현재까지 확인한 결과와 남은 예산을 바탕으로 다음 조회를 추천하는 방법을 Forensic-Claw에 구현했다. Windows의 Microsoft Edge와 Google Chrome에서 각각 다운로드 24건을 수집했다. 브라우저마다 첫 회차 8건으로 고정 조회 순서를 정하고 후속 16건에서 네 방식을 비교했다. 같은 조건에서 두 브라우저의 판정과 조회 비용은 일치했다. 조회 예산 3의 기본 조건에서 제안 방식과 최적 고정 순서는 각각 16건을 올바르게 판정했고, 한 단계씩 조회를 고르는 탐욕 방식은 12건을 판정했다. 프로필별로 조회할 아카이브가 달라지는 조건에서는 제안 방식과 탐욕 방식이 각각 16건을, 최적 고정 순서는 8건을 판정했다. 별도로 NVIDIA의 Qwen3.8-Flash-Next-NVFP4-QAD에 두 조건의 조회 순서를 요청했다. 아카이브 분리 조건의 응답과 기본 조건에서 추출한 정책은 제안 방식과 같은 판정과 비용을 보였다. 기본 조건의 원응답은 지정된 JSON 형식을 위반했다. 이 결과는 증거 조회의 우선순위가 자료 접근 구조와 남은 예산에 따라 달라짐을 보여준다.

**주제어** 대규모 언어 모델, Windows 디지털 포렌식, 증거 조회, 가설 검증, 브라우저 기록

## Abstract

When identical files are served from different sources, their hashes cannot distinguish the origins of their downloads. In a Windows forensic workflow, an analyst may need to inspect the browser profile or a URL chain, and the order of these checks affects the number of decisions that can be made within a limited budget. We implemented a budget-aware query planner in Forensic-Claw and captured 24 downloads each in Microsoft Edge and Google Chrome on Windows. For each browser, eight records were used to tune a fixed-order baseline and 16 were held out for evaluation. Both browsers produced identical replay outcomes under the controlled conditions. At a budget of three units under the standard cost schedule, the planner and the tuned fixed order each resolved 16 trials correctly, compared with 12 for a greedy policy. When the relevant archive depended on the observed profile, the planner and the greedy policy each resolved 16 trials, compared with eight for the tuned fixed order. We also asked NVIDIA Qwen3.8-Flash-Next-NVFP4-QAD to propose a policy for each of these two settings. Its valid policy in the archive setting and the policy extracted from its nonconforming standard-setting response matched the planner in verdicts and cost. The results show how source access and query costs affect the value of adaptive evidence retrieval.

**Keywords** large language models, Windows forensics, evidence retrieval, hypothesis testing, browser history

## Ⅰ. 서론

두 서버가 바이트가 같은 파일을 제공했다고 하자. 다운로드한 파일의 SHA-256이 기준 파일과 일치한다는 사실은 내용의 동일성을 뒷받침한다. 출처를 알려면 브라우저의 다운로드 행과 최종 URL을 연결해야 한다. 그런데 “대상 프로필에서 출처 A의 파일을 다운로드했는가”라는 질문이라면, 프로필을 먼저 확인했을 때 조회가 더 일찍 끝날 수도 있다. 다른 프로필로 확인되는 순간 이 명제를 반증할 수 있기 때문이다.

LLM이 Windows 포렌식 자료 검토를 보조할 때도 이 판단은 필요하다. 지금 갖고 있는 기록을 설명하는 작업과, 다음에 어떤 기록을 조회할지 선택하는 작업은 서로 다른 입력을 요구한다. 후자에는 후보 자료, 각 자료를 확인하는 데 드는 비용, 가능한 조회 결과가 주어져야 한다. 본 연구는 이 조건을 명시해 두 가지 질문을 검토한다. 첫째, 남은 예산과 후속 조회까지 고려한 방식은 언제 고정 순서 또는 한 단계씩 고르는 방식보다 더 많은 판정을 내리는가. 둘째, 같은 조건을 주었을 때 LLM이 제안한 조회 순서는 재생 가능한 형태이며 같은 비용으로 같은 판단에 도달하는가.

## Ⅱ. 관련 연구

Nisioti 등의 DISCLOSE는 공격 행위 사이의 관계와 검사 비용을 바탕으로 제한된 조사 예산에서 확인한 행위의 편익을 최대화한다[1]. Horsman은 수집 방법의 침습성을 고려한 확보 순서를 제안했다[2]. CAFE는 Windows의 여러 아티팩트가 특정 사건 주장을 어떻게 뒷받침하는지 비교한다[3]. 본 연구의 분석 단위는 브라우저 행위에 관한 명제 한 건이다. 같은 기록에서 읽을 수 있는 값이 무엇이고, 앞선 관측에 따라 다음 조회 대상이 달라지는지를 비용과 함께 평가한다.

검사 비용을 고려해 가설을 구분하는 문제는 능동학습에서도 다뤄졌다[4]. 본 연구에서 서로 다른 가설이 같은 판정으로 이어질 경우, 가설의 세부 차이까지 확인할 필요는 없다. 예를 들어 어떤 경로로 이동했든 최종 출처가 B라면 “출처 A에서 내려받았다”는 명제의 판정은 같다. 이때 현장 아티팩트가 실제로 어떤 값을 제공할 수 있는지는 별도로 확인해야 한다. NIST의 과학적 기반 검토도 기록의 생성 맥락과 관측 범위를 아티팩트 해석에 반영할 필요를 설명한다[5].

## Ⅲ. 연구 방법

### 3.1 Forensic-Claw에서의 다음 조회 추천

입력은 분석가가 설정한 가설, 관측 결과, 남은 예산이다. 각 가설에는 해당 명제의 판정과 자료별 예상 결과를 부여한다. 조회 결과가 들어오면 예상과 맞지 않는 가설을 제외한다. 남은 가설의 판정이 모두 같으면 지지 또는 반증을 반환한다. 지지와 반증이 함께 남으면 보류하고, 어느 가설도 관측과 일치하지 않으면 불일치를 표시한다.

추천기는 예산 안에서 가능한 다음 조회를 고려한다. 예상 결과별로 가설 집합을 나눈 뒤, 각 분기에서 남은 예산으로 추가 수행할 수 있는 조회를 탐색한다. 모든 분기에서 판정 가능한 가설 수를 합해 가장 큰 조회를 선택한다. 동률은 판정에 이르지 못한 분기를 포함한 전체 조회 비용으로 가른다. 가설의 가중치는 동일하게 두었다. Forensic-Claw의 CLI는 현재 판정, 남은 가설, 추천 조회와 비용, 예상 결과별 즉시 판정을 표시한다. 분석가는 실제 자료를 확인한 뒤 결과를 입력한다.

### 3.2 Windows 브라우저 기록 수집

Windows 11에서 Microsoft Edge 158.0.4370.33과 Google Chrome 157.0.8103.79를 각각 실행했다. 브라우저 제어에는 Playwright CLI 0.1.25를 사용했다. 회차마다 두 개의 새 브라우저 프로필을 만들어 총 8회씩 다운로드했다. 다운로드는 시작 URL과 리디렉션을 거쳐 두 최종 서버 중 하나에 도달했다. 두 서버는 같은 바이트를 반환하므로 파일 해시는 출처를 구분하지 못한다. 브라우저를 닫고 각 프로필의 History SQLite를 읽기 전용으로 조회해 완료 상태와 URL 체인을 확인했다. 절차상 지정한 프로필과 실제로 응답을 보낸 HTTP 서버의 로그를 판정 기준에 사용했다.

브라우저별로 세 회차에서 24건씩, 총 48건을 확보했다. 각 브라우저의 첫 회차 8건은 고정 순서 기준선을 정하는 데 사용했다. 후속 두 회차의 16건은 해당 순서를 선택하는 데 사용하지 않았다. 새 프로필과 HTTP 세션에서 자료를 다시 수집했으며, 실험 조건은 첫 회차와 같다.

### 3.3 조회 조건과 비교 방법

기본 조건의 질문은 “대상 프로필에서 최종 출처 A의 파일을 내려받았는가”이다. 조회 비용은 파일 해시 1, 프로필 확인 1, 중간 경로 확인 1, 최종 URL 확인 2, 서버 기록 조회 3, 전체 History 조회 4로 두었다. 비용에 따른 차이를 보기 위해 전체 History 비용을 2로 낮춘 조건과, 최종 URL 비용을 4로 높이고 서버 조회 비용을 2로 낮춘 조건도 비교했다.

프로필별 아카이브 조건에서는 두 프로필에 서로 다른 지정 출처를 부여했다. 조사 질문은 “확인된 프로필이 자신에게 지정된 출처에서 파일을 내려받았는가”이다. 프로필을 확인하는 비용은 1, 각 아카이브를 조회하는 비용은 2로 설정했다. 실제 브라우저 기록에 별도의 접근 조건을 적용해 재생했으며, 이 조건에서 별도 현장 자료를 수집하지 않았다.

비교 대상은 사전에 정한 체크리스트, 개발 회차에서 모든 순서를 비교해 고른 최적 고정 순서, 반대 판정의 가설 쌍을 비용 대비 가장 많이 구분하는 탐욕 방식, 여러 단계의 조회를 함께 고려하는 제안 방식이다. 네 방식은 같은 자료와 판정 규칙을 사용했다. 예산 1–5와 네 가지 비용·접근 조건에서 브라우저마다 1,280건씩, 총 2,560건의 정책 재생 결과를 얻었다. 정답 판정 건수와 함께 보류, 오판, 총 조회 비용을 기록했다.

### 3.4 LLM 비교

NVIDIA의 자체 호스팅 체크포인트 nvidia/Qwen3.8-Flash-Next-NVFP4-QAD[6]에 Pi를 통해 조회 정책을 요청했다. 기본 조건과 프로필별 아카이브 조건에서 예산은 3이고 추론 설정은 low였다. 모델은 평가 기록의 실제 관측값을 받지 않았으며, 다른 방식과 같은 가설표와 비용표를 받았다. 입력마다 한 번 요청했고, 응답에는 조회 항목과 결과별 후속 조회를 JSON으로 기재하도록 했다. 생성된 두 정책을 Edge와 Chrome의 평가 기록에 각각 재생했다. 브라우저별로 모델을 다시 호출하는 대신, 같은 정책을 적용해 기록에 따른 결과 차이를 확인했다.

## Ⅳ. 실험 결과

### 4.1 조회 방식별 판정

Edge와 Chrome에서 각 1,280건의 재생 결과를 비교했다. 동일 조건에서 조회 순서, 판정, 비용이 모두 일치했다. 표 1은 두 브라우저에 공통인 결과이며, 각 셀의 분모 16은 브라우저 한 종류의 평가 기록 수다. 뒤 숫자는 해당 16건에 사용한 총 조회 비용이다.

**표 1. 예산 3에서의 정답 판정 건수와 총 조회 비용**

| 조건 | 체크리스트 | 최적 고정 순서 | 탐욕 | 제안 |
|---|---:|---:|---:|---:|
| 기본 | 12/16 · 42 | 16/16 · 32 | 12/16 · 26 | 16/16 · 32 |
| 전체 History 비용 감소 | 16/16 · 48 | 16/16 · 32 | 16/16 · 32 | 16/16 · 32 |
| 최종 URL 비용 증가 | 12/16 · 42 | 16/16 · 32 | 12/16 · 26 | 16/16 · 32 |
| 프로필별 아카이브 | 0/16 · 32 | 8/16 · 40 | 16/16 · 48 | 16/16 · 48 |

기본 조건에서 제안 방식과 최적 고정 순서는 모두 프로필을 먼저 확인했다. 대조 프로필로 확인된 8건은 그 단계에서 반증했고, 대상 프로필의 나머지 8건에는 최종 URL 조회를 추가했다. 두 방식은 각각 총 비용 32에서 16건을 판정했다. 같은 예산에서 탐욕 방식은 12건을 판정하고 4건을 보류했다. 예산을 4로 늘리면 탐욕 방식도 16건을 판정했고, 총 비용은 34였다. 전체 History를 저렴하게 조회할 수 있는 조건에서는 예산 3에서 세 방식이 모두 같은 판정 건수와 비용을 보였다.

프로필별 아카이브 조건에서는 프로필 확인 후 어느 아카이브를 선택할지가 판단을 좌우했다. 예산 3에서는 프로필 확인과 아카이브 한 곳을 조회할 수 있다. 고정 순서는 두 프로필에서 같은 아카이브를 우선 조회했으므로 8건을 판정했다. 탐욕 방식과 제안 방식은 확인한 프로필에 따라 다른 아카이브를 골라 16건을 판정했다. 그림 1은 예산이 달라지면 이 차이가 어떻게 변하는지 보여준다.

@FIG budget-curves.png
**<Fig. 1> 예산별 정답 판정 건수: 기본 조건과 프로필별 아카이브 조건**

### 4.2 Qwen3.8-Flash-Next-NVFP4-QAD가 제안한 조회 정책

프로필별 아카이브 조건에서 Qwen은 프로필을 먼저 조회하고, 그 결과에 맞는 아카이브를 확인하도록 했다. 이 정책은 16건을 총 비용 48에 판정했다. 기본 조건에서는 원응답에 설명이 붙어 JSON 전용 형식 검사를 통과하지 못했다. 부가 분석으로 코드 블록 속 정책을 추출해 그대로 재생하자 16건을 총 비용 32에 판정했다. 이 정책도 프로필을 먼저 확인하고 대상 프로필에서만 최종 출처를 조회했다. Edge와 Chrome에 같은 정책을 적용했을 때 두 브라우저의 결과가 일치했다. 각 조건의 판정 건수와 비용은 Forensic-Claw가 계산한 정책과도 같았다.

## Ⅴ. 고찰

기본 조건의 결과는 더 적합한 첫 조회를 고르면 이후 조회에 쓸 예산이 남는다는 점을 보여준다. 이 조건에서는 가설과 비용을 잘 반영한 고정 순서로도 충분했다. 아카이브가 분리된 조건에서는 조회 순서 자체를 미리 고르는 일보다, 앞서 확인한 값에 따라 다른 자료를 선택하는 일이 중요했다. 이 경우 한 단계씩 고르는 방식으로도 모든 평가 기록을 판정할 수 있었다.

Qwen의 응답은 가설과 비용이 사전에 주어진 두 조건에서 적절한 조회 순서를 산출할 수 있다는 사례를 제공한다. 기본 조건에서는 정책의 내용과 인터페이스의 요구 사항이 달랐다. 사람이 읽을 수 있는 설명이 포함됐지만 자동 재생기는 지정된 형식으로 응답을 읽을 수 없었다. 이 실험에는 두 번의 LLM 호출만 포함됐으므로, 모델 간 우열이나 같은 모델의 반복 실행 안정성은 판단할 수 없다.

재생 실험에서 오판은 없었다. 자료가 등록된 가설 중 하나와 맞도록 수집됐고, 모든 비교 방식이 같은 판정 규칙을 사용했다는 점을 고려해야 한다. 실제 사건에서는 모형 밖의 행위가 등록 가설과 같은 관측을 만들 수 있다. 또한 조회 비용은 모형에서 설정한 단위이며 현장 조사 시간은 측정하지 않았다. 브라우저별 평가 회차는 새 프로필에서 실행했으나 동일한 여덟 조건을 반복했다. 두 제품 모두 Chromium 기반이므로 결과를 다른 브라우저 엔진의 아티팩트 구조에 일반화할 수 없다. 다른 사건 유형에 적용하려면 가설과 증거 관계를 정의하는 데 드는 비용과 실제 조회 시간을 함께 평가해야 한다.

## Ⅵ. 결론

본 연구는 LLM을 활용한 Windows 포렌식에서 어떤 자료를 먼저 조회할지 비교할 수 있도록, 실제 브라우저 기록에 가설과 조회 비용을 대응시켰다. Forensic-Claw에 구현한 추천 방식은 기본 조건에서 탐욕 방식보다 더 많은 평가 기록을 판정했고, 최적화한 고정 순서와는 같았다. 자료 위치가 프로필에 따라 달라지면 관측에 따라 조회를 바꾸는 방식이 고정 순서보다 유리했다. Qwen이 생성한 정책도 비교한 두 조건에서 같은 판정 건수와 비용을 보였다. 실제 적용에서는 먼저 가설을 구분할 수 있는 자료와 접근 비용을 적고, 각 조회 결과가 다음 판단에 어떤 영향을 주는지 남겨야 한다.

## 데이터 및 코드 가용성

정규화한 브라우저 기록, 실험에 사용한 사건 모형, 정책별 재생 결과, LLM 원응답과 채점 자료를 보존했다. 브라우저 기록 수집과 결과 재생 절차를 함께 제공한다.

## 참고문헌

[1] A. Nisioti et al., “Data-Driven Decision Support for Optimizing Cyber Forensic Investigations,” IEEE Transactions on Information Forensics and Security. https://aronlaszka.com/papers/nisioti2021data.pdf

[2] G. Horsman, 2022, “An order of data acquisition for digital forensic investigations,” Journal of Forensic Sciences. https://doi.org/10.1111/1556-4029.14979

[3] H. Shin and J. Park, “CAFE: A Claim-Level Cross-Artifact Verification Framework for Assessing the Reliability of Windows Forensic Evidence under Anti-Forensic Manipulation,” DFRWS presentation. https://dfrws.org/presentation/cafe-a-claim-level-cross-artifact-verification-framework-for-assessing-the-reliability-of-windows-forensic-evidence-under-anti-forensic-manipulation/

[4] D. Golovin, A. Krause, and D. Ray, 2010, “Near-Optimal Bayesian Active Learning with Noisy Observations,” NeurIPS. https://arxiv.org/abs/1010.3091

[5] J. Lyle et al., 2022, “Digital Investigation Techniques: A NIST Scientific Foundation Review,” NISTIR 8354. https://doi.org/10.6028/NIST.IR.8354

[6] NVIDIA, “Qwen3.8-Flash-Next-NVFP4-QAD,” model card. https://huggingface.co/nvidia/Qwen3.8-Flash-Next-NVFP4-QAD
