# 나노봇 전격 해설 Part 2: 핵심 뇌와 반복 루프 🧠

Part 2에서는 나노봇이 실제로 멈추지 않고 생각하며, 과거의 기억을 까먹지 않고 보존하는 핵심 두뇌 부품들을 뜯어볼 거예요. 나노봇의 **심장(loop.py)**, **프롬프트 팩토리(context.py)**, 그리고 **장기 기억 장치(memory.py)**가 바로 오늘의 주인공입니다!

---

## 1. `nanobot/agent/loop.py` (나노봇의 심장)
이전에 살짝 보았던 나노봇의 심장부 파일이에요. 전체 구조를 보면 생각보다 치밀하게 짜여 있답니다.

```python
"""Agent loop: the core processing engine."""
# 나노봇을 살아 숨 쉬게 하는 가장 핵심 엔진(루프)이에요.
from __future__ import annotations
import asyncio 
# 등등 필요한 부품들을 가져옵니다.

class AgentLoop:
    # 에이전트 루프 클래스! 여기서 모든 일이 일어납니다.

    def __init__(self, bus, provider, workspace...):
        # 봇이 태어날 때(시작될 때) 세팅을 하는 곳이에요.
        # - bus: 신경망 핏줄 (메시지 전달)
        # - provider: 챗GPT 같은 진짜 뇌 (LLM)
        # - tools: 도구상자 (웹 검색, 파일 읽기 등)
        # - subagents: 분신술 매니저 (꼬마 로봇들)

    def _register_default_tools(self):
        # 도구상자(가방)에 쓸 수 있는 도구들을 차곡차곡 넣어두는 함수예요.
        # 파일을 읽고(ReadFileTool) 쓰는 도구, 인터넷 웹브라우저(WebFetchTool), 알람(CronTool) 등을 장착!

    async def _run_agent_loop(self, initial_messages, ...):
        # 여기가 **진짜 생각하는 과정(루프)**입니다!
        # 최대 40번까지 속으로 생각하고(반복) 대답을 찾는 과정을 진행해요.
        while iteration < self.max_iterations: # 최대 40번 반복
            # 1. 뇌(LLM)에게 현재 상황을 주고 "어떻게 할까?" 물어봄.
            response = await self.provider.chat_with_retry(...) 
            
            # 2. 뇌가 "도구(인터넷 검색 등)를 써보자!" 라고 하면?
            if response.has_tool_calls:
                # 지정된 도구들을 부지런히 사용해서 결과를 가져와요.
                results = await asyncio.gather(...) 
                # (도구 사용 결과를 다음 뇌의 생각 재료로 넘겨줌)
            else:
                # 3. 뇌가 "아, 정답을 알았어!" 라고 하면 혼잣말을 멈추고 최종 대답을 뱉어냄!
                final_content = response.content
                break

    async def run(self):
        # 지난 리뷰에서 본 '무한 반복 대기실' 이에요. 
        # 누군가 말을 걸면 1초만에 낚아채서 위에서 설명한 '생각하는 과정_run_agent_loop'으로 넘깁니다!

    async def _process_message(self, msg, ...):
        # 메시지를 받았을 때, 이전 대화 내역(Context)과 섞어서 뇌로 보내기 좋게 포장해 주는 함수예요.
```

---

## 2. `nanobot/agent/context.py` (프롬프트 공장장)
AI에게 무작정 "안녕"이라고 보내면 "넌 누구지?" 하겠죠? 그래서 AI가 내 명령을 잘 따르도록 기본 캐릭터 설정과 과거 기억을 섞어주는 포장(프롬프트) 공장장 파일이에요.

```python
"""Context builder for assembling agent prompts."""

class ContextBuilder:
    # AI에게 보낼 편지(프롬프트)를 정성스레 조립하는 공장장!

    def build_system_prompt(self):
        # "너는 나노봇이야. 윈도우(혹은 맥) 컴퓨터에 살고 있고, 도구를 쓸 수 있어."라는 
        # 로봇의 자아(아이덴티티)와 주의사항을 적은 문서를 만들어주는 함수예요.

    def _get_identity(self):
        # 로봇이 윈도우용 파이썬 환경에 있는지, 맥북 환경인지 스스로 깨닫게 해주고, 
        # "인터넷 정보는 조심해서 믿어라!" 등 꼭 지켜야 할 규칙을 훈구해 줍니다. 

    def _build_runtime_context(self):
        # "지금은 한국 시간 오후 3시야. 넌 디스코드에 있어." 같은 
        # 현재 시공간 정보를 편지 맨 위에 몰래 포스트잇처럼 붙여주는 역할!

    def build_messages(self, history, current_message...):
        # (과거 대화 내역 + 로봇 자아 설정 + 이번에 새로 들어온 질문)
        # 이 세 가지를 예쁘게 합쳐서 AI 뇌가 읽기 좋게 최종 배달 상자로 만들어 주는 함수!
        # 필요하면 사진이나 이미지도 분석할 수 있게 덧붙여 주죠. (_build_user_content)
```

---

## 3. `nanobot/agent/memory.py` (나노봇의 장기 기억 장치)
나노봇과 어제 했던 이야기를 오늘 또 물어봐도 기억하는 이유가 바로 이 파일 덕분이에요. 대화가 너무 길어지면 뇌가 터지기 때문에 똑똑하게 요약(Consolidate)해서 보관해요.

```python
"""Memory system for persistent agent memory."""

class MemoryStore:
    # 창고지기 역할! 디스크 폴더(memory)에 진짜로 파일을 읽고 쓰는 녀석이에요.
    # - MEMORY.md: 가장 중요한 팩트(사용자의 이름, 직업 등)를 요약해서 저장하는 파일
    # - HISTORY.md: 대화 로그를 타임라인처럼 주욱~ 적어두는 파일

    async def consolidate(self, messages, provider, model):
        # [기억 압축기!] 대화 내용이 100줄을 넘어가기 시작하면, AI에게 
        # "이 대화들에서 중요했던 내용만 3줄로 요약해서 창고에 저장(save_memory)해!" 라고 시키는 함수예요.
        
class MemoryConsolidator:
    # 기억 압축 관리소장! 언제 기억을 압축해야 할지 눈치를 보는 역할이에요.

    async def maybe_consolidate_by_tokens(self, session):
        # 대화방의 글자 수(Token)를 세어보고, 
        # "어어? 뇌(AI)가 한 번에 읽을 수 있는 한계치에 다와가네? 안 되겠다. 빨리 오래된 대화부터 창고로 압축해서 넘겨라!" 
        # 하고 지시를 내리는 아주 영리한 함수입니다. 
        # 덕분에 오류 없이 1시간이고 10시간이고 봇과 떠들 수 있어요.
```

---
> 와! 이제 나노봇이 **어떻게 계속 살아있고 (loop.py)**, **어떤 룰과 과거 기억(context.py)을 바탕으로 생각하며**, **대화가 길어져도 까먹지 않고 똑똑하게 요약 보관(memory.py)**하는지 '뇌와 심장' 작동 원리를 완벽하게 알게 되었습니다! 
>
> 3단계인 Part 3에서는 나노봇의 팔과 다리가 되어주는 신기한 **Tools(도구상자)**와 **Subagent(분신술)** 코드에 대해 알려드릴게요!🚀
