# 나노봇 전격 해설 Part 4: 내부 신경망과 메신저 채널 📡

Part 4에서는 뇌와 손발이 만들어진 나노봇이 **사용자와 어떻게 대화방을 연결(Channels)**하고, 수많은 질문을 꼬이지 않게 **안전하게 전달(Bus)**하는지 알아볼게요!

---

## 1. `nanobot/bus/queue.py` (우체국 택배 큐)
나노봇 몸통 안에서 메시지들이 길을 잃지 않도록 줄을 세워주는 "우편집중국" 파일이에요.

```python
"""Async message queue for decoupled channel-agent communication."""

class MessageBus:
    # 대화방(채널)과 뇌(에이전트) 사이를 이어주는 비동기 택배 버스!
    # "이 질문이 먼저 왔어, 저 질문이 먼저 왔어?" 싸우지 않게 확실하게 줄(Queue)을 세웁니다.

    def __init__(self):
        # 1. 밖에서 뇌로 들어오는 질문 줄 (inbound)
        self.inbound = asyncio.Queue()
        # 2. 뇌에서 밖으로 나가는 대답 줄 (outbound)
        self.outbound = asyncio.Queue()

    async def publish_inbound(self, msg):
        # [우체통 넣기] 디스코드나 카톡에서 문자가 오면, 안쪽(inbound) 줄의 맨 끝에 세웁니다.

    async def consume_inbound(self):
        # [우편물 빼기] 뇌(루프)가 "다음 질문 가져와!" 할 때, 줄 가장 선두에 있는 메시지를 쏙 빼줍니다.

    async def publish_outbound(self, msg):
        # [우체부 출동] 뇌가 대답을 다 만들면 바깥쪽(outbound) 줄의 맨 끝에 세웁니다.
```

---

## 2. `nanobot/channels/manager.py` (입장권 검사 및 관리소장)
텔레그램, 디스코드, 슬랙 등 수많은 메신저와 나노봇을 연결할 때, 모두 정상적으로 작동되도록 한꺼번에 관리해 주는 소장님이에요.

```python
"""Channel manager for coordinating chat channels."""

class ChannelManager:
    # 열려있는 채팅방들을 모두 감시하고 전송을 관리하는 역할구역
    
    def _init_channels(self):
        # 나노봇의 빈칸(config)을 뒤져서, 사용자가 "디스코드 켤래! 텔레그램 켤래!" 라고 켜둔 걸 확인하고
        # 그 메신저들을 실제로 사용할 수 있게 준비시켜요.

    def _validate_allow_from(self):
        # 아무나 우리 봇을 부려먹으면 안 되겠죠? 
        # "이 메신저에서 말 거는 사람이 허락된 사람(allow_from)이 맞는지 검사해라!" 라고 
        # 설정 파일의 화이트리스트 명단을 팩트 체크 합니다.

    async def start_all(self):
        # "자, 준비된 메신저들 모두 켜서 질문 받을 준비해!" 라고 출근을 지시합니다.

    async def _dispatch_outbound(self):
        # 우편집중국(bus)의 '나가는 줄(outbound)'에서 대답을 하나씩 꺼내온 다음, 
        # "이 답장은 디스코드 방에 가야 해! 저 답장은 텔레그램으로 가야 해!" 하고 목적지로 쐈는지 확인해요.

    async def _send_with_retry(self, channel, msg):
        # 만약 인터넷이 끊겨서 카톡/메시지 전송이 실패했다면? 
        # 포기하지 않고 1초 후, 2초 후, 4초 후 타이머를 걸어가며 될 때까지 재전송(재도전)을 합니다! (진짜 착한 기능!)
```

---

## 3. `nanobot/channels/base.py` (메신저 번역 어댑터 뼈대)
디스코드 서버가 쓰는 언어 다르고, 슬랙이 쓰는 언어가 다르잖아요? 어떤 메신저든 나노봇이랑 똑같은 방법으로 이야기할 수 있도록 만들어주는 **통역관의 뼈대(베이스)**입니다.

```python
"""Base channel interface for chat platforms."""

class BaseChannel(ABC):
    # 나는 기본 뼈대다! 텔레그램, 디스코드 모두 나를 복사해서 틀을 만들어라!

    async def transcribe_audio(self, file_path):
        # 누군가 메신저로 타자를 안 치고 "음성 메시지"를 보냈다면? 
        # 이걸 텍스트 글씨로 번역(Transcribe)해주는 똑똑한 기본 능력이에요.

    def is_allowed(self, sender_id):
        # 설정 파일에서 "모두 허가(*)"인지, "내 아이디만 허가"인지 보고
        # 방금 말 건 사용자의 출입증을 한 번 더 검사합니다.

    async def _handle_message(self, ...):
        # 메신저에서 문자가 성공적으로 오면 호출돼요. 
        # 1. "넌 출입 금지야" 인지부터 확인!
        # 2. 통과면, 내용(글씨, 사진 등)을 포장해서 위에서 본 우편집중국(bus.publish_inbound)으로 밀어 넣어요!
```

---

## 4. `nanobot/channels/` 메신저별 특수 파일들
`base.py`의 뼈대를 물려받은 실제 메신저 작동 파일들이에요. (`discord.py`, `telegram.py`, `slack.py`, `dingtalk.py` 등등)

- 이 파일들은 복잡해보이지만 본질은 아주 단순해요!
- **`start()`**: "텔레그램/디스코드 서버에 내 비밀번호(토큰)를 주고 접속(로그인)합니다."
- **`send()`**: "우리 나노봇의 뇌가 만든 대답을 가지고, 텔레그램 화면에 글씨로 쏘아 올립니다." 

---
> 이제 밖에서 들어온 수많은 메신저 알람들이 어떻게 `channels` 통역기를 거쳐 `bus`(우체국 줄)를 타고 나노봇의 심장으로 들어가는지 그 길이 훤히 보일 거예요!
>
> 5단계인 최종 **Part 5** 에서는 나노봇이 알아듣는 **슬래시 특수 명령어(/help)** 처리 방식과 알람시계(**cron/session**)를 한 번에 싹 다 보여드릴게요!🚀
