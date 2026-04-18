---
name: skill-creator
description: Create or package forensic-claw skills when the user needs a reusable skill folder with validation and packaging helpers.
---

# Skill Creator

Use this skill when the user wants to scaffold, validate, or package a new skill.

## Use Cases

- Create a new skill folder with starter content
- Validate a skill before packaging
- Produce a distributable `.skill` archive

## Available Scripts

- `scripts/init_skill.py`
- `scripts/quick_validate.py`
- `scripts/package_skill.py`

## Guidance

- Keep skill names in lowercase hyphen-case.
- Put the skill definition in `SKILL.md`.
- Use `scripts/`, `references/`, and `assets/` only when they add clear value.
