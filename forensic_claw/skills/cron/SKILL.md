---
name: cron
description: Schedule recurring or delayed local follow-up tasks when the user needs reminders or unattended reruns.
---

# Cron

Use this skill when the task should run later or on a schedule instead of immediately.

## Use Cases

- Repeat a health check every few minutes
- Schedule a delayed reminder
- Re-run a lightweight forensic query on a cadence

## Guidance

- Prefer cron only when the user benefits from asynchronous follow-up.
- Keep scheduled payloads narrow and deterministic.
- Use timezone-aware scheduling when the exact local time matters.
