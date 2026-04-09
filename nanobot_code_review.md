# 나노봇 핵심 코드 리뷰 (중학생도 이해할 수 있는 쉬운 설명!)

안녕! 나노봇(nanobot)은 우리가 질문을 하면 AI가 생각해서 답변해주고, 필요하면 컴퓨터 내의 파일도 읽고 쓸 수 있는 '똑똑한 인공지능 비서'야.
나노봇 안에는 수천 줄의 코드가 있지만, 그 중에서도 가장 '심장' 역할을 하는 **"핵심 작동 엔진(AgentLoop)"**의 코드를 한 줄 한 줄 아주 쉽게 설명해 줄게!

## 🤖 핵심 코드: 나노봇은 어떻게 계속 깨어있을까? (`nanobot/agent/loop.py`)

나노봇이 우리 말을 듣고 대답하기 위해 항상 돌아가고 있는 핵심 `run` 함수 코드야.

```python
async def run(self) -> None:
    # 1. 나노봇 켜기 (준비 운동)
    self._running = True
    await self._connect_mcp()
    logger.info("Agent loop started")

    # 2. 나노봇이 켜져 있는 동안 계속 반복 (무한 루프)
    while self._running:
        try:
            # 3. 누군가 메신저나 터미널로 말을 걸었는지 '딱 1초만' 기다려보기
            msg = await asyncio.wait_for(self.bus.consume_inbound(), timeout=1.0)
            
        # 4. 1초 동안 아무도 말을 안 걸었다면?
        except asyncio.TimeoutError:
            continue  # 멈추지 않고, 다시 while문 처음으로 돌아가서 또 기다림!
            
        # 5. 누군가 강제로 나노봇을 끄려고 했다면? (예: Ctrl+C)
        except asyncio.CancelledError:
            if not self._running or asyncio.current_task().cancelling():
                raise  # 진짜 꺼야 하는 상황이면 시스템을 종료함
            continue
            
        # 6. 알 수 없는 다른 코드 에러가 났다면?
        except Exception as e:
            logger.warning("Error consuming inbound message: {}, continuing...", e)
            continue  # 에러가 났다고 나노봇이 죽어버리면 안 되니까, 경고만 남기고 계속 실행함

        # ------ (위의 관문을 통과했다면 사용자가 보낸 '메시지'를 성공적으로 받은 것!) ------

        # 7. 받은 메시지의 앞뒤 빈칸(쓸데없는 공백)을 깔끔하게 지워줌
        raw = msg.content.strip()
        
        # 8. 긴급 명령어인지 확인하기 (예: /stop 명령어)
        if self.commands.is_priority(raw):
            ctx = CommandContext(msg=msg, session=None, key=msg.session_key, raw=raw, loop=self)
            result = await self.commands.dispatch_priority(ctx) # 긴급 명령이라면 AI 생각 없이 바로 쓱싹 처리!
            if result:
                await self.bus.publish_outbound(result) # 처리 결과를 사용자에게 바로 답장 보냄
            continue # 긴급 명령어 처리가 끝났으니 일반 대화는 생략하고 다시 처음으로 대기하러 감
            
        # 9. 긴급명령어가 아닌 일반 질문이었다면? '작업(Task)'을 만들어서 AI에게 생각하고 답변하라고 넘김!
        task = asyncio.create_task(self._dispatch(msg))
        
        # 10. 이 작업(Task)이 현재 진행 중이라는 걸 기억해두기 위해 명단에 잘 적어둠
        self._active_tasks.setdefault(msg.session_key, []).append(task)
        
        # 11. 작업이 다 끝나면(AI가 답장을 다 마치면), 진행 중 명단에서 이 작업을 자동으로 지우도록 청소 규칙을 설정함
        task.add_done_callback(lambda t, k=msg.session_key: self._active_tasks.get(k, []) and self._active_tasks[k].remove(t) if t in self._active_tasks.get(k, []) else None)
```

---

## 📖 한 줄 한 줄 쉬운 해설 요약

1. **준비 운동 단계 (1번)**  
   나노봇을 켤 준비를 해. 내부적인 연결망(MCP) 등을 셋팅하고, 화면에 "에이전트 루프가 시작되었습니다!"라고 띄워서 시작을 알려.

2. **무한 대기 (`while self._running:`) (2번)**  
   우리가 컴퓨터 전원을 끄기 전까지 나노봇은 계속 귀를 열고 들어야 해. 그래서 "나노봇이 켜져있는 동안 이 과정을 무한히 반복해라"라고 명령해두는 거야.

3. **1초의 기다림 (3~6번)**  
   카카오톡을 기다리는 것처럼, 누군가 채팅이나 명령어를 보냈는지 **'딱 1초만' 기다려 보는** 코드야. 1초 동안 답변이 없으면 멈춰있지 않고 바로 다시 1초를 세기 시작해. 중간에 에러가 발생해도 나노봇 프로그램 자체가 꺼지지 않도록 보호하는 역할도 하지.

4. **새치기! 우선순위 명령어 (7~8번)**  
   들어온 메시지가 일반 대화가 아니라 "나노봇 당장 멈춰!"(`/stop`)처럼 긴급한 명령어일 수 있잖아? 이럴 땐 복잡한 AI 뇌를 거치지 않고 가장 최우선으로 빠르게 처리하고 바로 답장해 버려.

5. **AI에게 일 넘기기 (`create_task`) (9~11번)**  
   긴급 명령어가 아닌 평범한 질문이라면, 이제 본격적으로 똑똑한 AI의 뇌(LLM)로 질문을 넘겨. `_dispatch(msg)` 안에는 "AI가 생각하기 → 검색이나 파일 읽기 등 도구 사용하기 → 최종 대답 만들어 보내기"의 긴 과정이 다 들어있어. 
   중요한 건, 이 과정을 백그라운드 **작업(Task)**으로 분리해서 알아서 생각하게 맡겨둔다는 점이야! 덕분에 한 질문에 대해 AI가 열심히 생각하는 와중에도, 나노봇은 곧바로 다른 사람의 또 다른 질문을 받을 준비를 할 수 있게 돼. (엄청난 멀티태스킹!)

이처럼 나노봇의 핵심 코드는 주기적으로 질문이 왔는지 짧게 짧게 확인하고, 질문이 오면 AI에게 분석을 시킨 뒤 자신은 멈추지 않고 또 다른 질문을 계속 받는 '아주 성실한 우체국장'처럼 동작한단다!
