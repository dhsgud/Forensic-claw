# 나노봇 전격 해설 Part 5: 명령어 처리와 부가 기능 ✨

나노봇 해설의 마지막! Part 5에서는 대화방 기록을 관리하는 **세션(Session)**, 특정 시간에 맞춰 움직이는 **알람(Cron)**, 슬래시(`/`) 명령어를 전담하는 **명령어 처리기(Command)**, 그리고 진정한 뇌를 불러오는 **프로바이더(Providers)** 친구들을 알아볼게요.

---

## 1. `nanobot/command/router.py` (특수 명령어 처리 리모컨)
사용자가 안녕? 이라고 말하지 않고 `/help`, `/clear` 처럼 슬래시(`/`)를 붙여서 말하면 나노봇을 직접 컨트롤하는 리모컨 버튼으로 인식해야 하잖아요? 그걸 처리해 주는 파일이에요.

```python
"""Minimal command routing table for slash commands."""

class CommandRouter:
    # "이 버튼(/)을 누르면 이런 행동을 해라!" 하고 명령어를 분류해주는 리모컨 라우터(분배기)입니다.

    def __init__(self):
        # 1. priority (우선순위): /stop 처럼 로봇 동작 자체를 긴급하게 멈출 때 쓰는 특수칸
        # 2. exact (정확히 일치): /clear (기억 지워!) 처럼 단어 전체가 똑같을 때 발동!
        # 3. prefix (접두사): /team 처럼 문장 맨 앞에 특정 단어가 오면 발동!

    async def dispatch(self, ctx):
        # 방금 막 사용자가 친 문장을 검사해서 
        # "오! 이거 슬래시(/) 명령어네? 나노봇아 생각하지 말고 그냥 내가 시킨 정해진 행동(명령)을 수행해!" 
        # 라고 특수 동작을 덮어씌워 줍니다.
```

---

## 2. `nanobot/session/manager.py` (대화방 기억 장부 관리인)
나노봇은 여러 방에서 동시에 일할 수 있어요. 텔레그램 A 채팅방의 대답이 디스코드 B 채팅방으로 섞여 들어가면 큰일 나겠죠? 그래서 대화방(Session)마다 장부를 따로 쓰는 파일이에요.

```python
"""Session management for conversation history."""

class Session:
    # "디스코드 A방의 장부입니다!" 하나의 채팅방 기록을 들고 있는 파일철이에요.
    
    def add_message(self, role, content):
        # [기록 추가] 사용자가 말한 내용이나 로봇이 대답한 내용을 장부 맨 밑에 한 줄 추가합니다.

    def get_history(self, max_messages=500):
        # [기억 회상] AI 뇌가 "우리 아까 무슨 얘기 했었지? 최근 500줄만 줘 봐" 라고 하면
        # 깔끔하게 기록을 정리해서 AI에게 과거 대화 내역 전체를 넘겨줍니다.

class SessionManager:
    # "모바일 텔레그램 장부, PC 슬랙 장부 다 가져와봐!"
    # 이 클래스는 수많은 Session 파일철(.jsonl 파일)들을 모아두고 관리하는 중앙 관리소예요.
    
    def get_or_create(self, key):
        # 누군가 말을 걸면, "이 사람 장부 있나?" 찾아보고 없으면 새 장부를 만들어 줘요.
        
    def save(self, session):
        # 실컷 대화가 끝난 로봇의 장부를 컴퓨터 파일(.jsonl)에 잃어버리지 않게 저장(Save)합니다.
```

---

## 3. `nanobot/cron/service.py` (나노봇 전용 알람 시계)
우리 폰에 있는 '알람 앱'과 똑같은 파일이에요! 나노봇에게 "매일 아침 9시마다 뉴스 알려줘"라고 약속을 걸어둘 수 있죠.

```python
"""Cron service for scheduling agent tasks."""

class CronService:
    # 나노봇 몸 안에 있는 알람 시계(스케줄러) 랍니다!
    
    def _arm_timer(self):
        # 설정된 알람(예: 다음 9시)이 몇 초 남았는지 계산해서, 그 시간 동안 로봇에게 "기다려!" 하고 타이머를 걸어둡니다.

    async def _on_timer(self):
        # 삐비빅! 시간이 되면 알람이 울리며 이 함수가 실행돼요.
        # "지금 알람 울린 스케줄이 뭔지 확인하고, 나노봇에게 당장 그 일을 시켜라!" 하고 
        # 뇌(AgentLoop)에게 특별 지시를 내립니다. (_execute_job)

    def add_job(self, name, schedule, message...):
        # [알람 추가] 우리가 'cron 알람 도구'를 쓰면 이 함수가 실행돼서 "아침 9시, 뉴스 읽기"라는 새 알람을 목록에 저장해요.
```

---

## 4. `nanobot/providers/` (천재 AI 두뇌를 빌려오는 통로)
나노봇 몸체에는 사실 똑똑한 뇌가 안 들어있어요. 뇌는 밖(OpenAI, Anthropic 등)에서 인터넷으로 빌려와야 해요! 

- **`base.py`**: "어떤 뇌를 갖다 쓰든 간에, 입력은 이렇게 주고 출력은 저렇게 빼내라!" 라고 정해둔 기본 틀.
- **`openai_compat_provider.py`**: ChatGPT(OpenAI API)처럼 인터넷을 통해 가장 유명한 뇌를 연결하고 답변을 받아오는 파이프 파일들입니다.

---
> 짝짝짝! 👏👏👏 
> 축하합니다! 이렇게 해서 많고 많던 124개의 파이썬 코드들이 도대체 무얼 하는지 **수만 줄의 뼈대 논리**를 Part 1부터 Part 5까지 모두 훑어보았습니다! 
> 
> 파일 이름만 보면 무서웠겠지만, 로봇의 "입력 -> 머리로 이동 -> 생각(기억/도구) -> 출력" 이라는 순서로 보니까 정말 쉽죠?
> 만약 5탄까지 보신 뒤에 "이 파일 코드를 진짜 한 글자씩 낱낱이 파헤쳐서 코딩 공부를 하고 싶어!" 하는 특별한 파일이 있다면 언제든 편하게 알려주세요! 😊
