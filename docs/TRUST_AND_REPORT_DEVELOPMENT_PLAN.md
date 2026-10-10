# Evidence trust and report development

## Scope

Complete the existing partially implemented evidence workflow, plus Evidence Object validation,
HallucinationDetector, VERIFIED/PARTIAL/FLAGGED/UNVERIFIED, and HTML/PDF reports.
Use a general forensic report, as requested when an official prosecutor form cannot be found.
Do not add the other unimplemented roadmap modules (Volatility, MFT/USN, NPKI/HWP,
Neo4j, MITRE mapping, RansomwareTracer).

## Delivery order

1. [x] Preserve acquired sources, automatically register evidence, and persist timeline/graph/wiki.
       Carry case identity and original hashes through retrieval; recheck current bytes.
2. [x] Validate mandatory source/timestamp/hash fields before model input. Add conservative claim
       checks for missing citations, unsupported quotes, paths and timestamps. Assign trust grades
       per claim; do not treat duplicate chunks or copied files as independent corroboration.
3. [x] Connect trusted retrieval and post-generation checks to reports, foreground and background
       analysis. Distinguish missing evidence, failed analysis, observations and inferences.
4. [x] Export the same checked report to Markdown, escaped offline HTML and Korean PDF.
       Add download routes and template selection; include assets in Windows builds.
5. [x] Finish existing Windows/browser adapters, background status, and graph provenance without
       inventing causal relationships from co-occurrence. Verify behavior with temporary sources,
       deterministic model-boundary fakes, PDF rendering, full pytest and Ruff.

## Trust policy

- UNVERIFIED: required integrity verification failed or is unavailable; excluded from model input.
- FLAGGED: missing/invalid provenance, unsupported claim, quote, path or timestamp; reviewer needed.
- PARTIAL: an extractive observation supported by one integrity-checked source.
- VERIFIED: the same extractive observation supported by at least two distinct original artifacts
  with different content hashes. This is a provenance grade, not legal admissibility or a measured
  probability of truth. Free paraphrases/inferences stay FLAGGED until reviewed.

Existing evidence is not silently upgraded. Acquisition time/file modification time must be labeled
separately from event time. Hashes are computed in code, never supplied by the model.

## Acceptance checks

- Tampered, missing, malformed and cross-case evidence cannot ground model claims.
- A fabricated provider response cannot become a VERIFIED report finding.
- Search absence cannot produce a clean bill of health.
- Case ingestion produces navigable source/evidence references and reproducible exports.
- HTML escapes source/model content, PDF displays Korean and long paths, and exports have the same
  trust decisions. Interrupted export does not replace an existing report with a partial file.
- No live LLM accuracy claims or official-form claims without independent evaluation.

## Delivered behavior and limits

- Sources are copied with acquisition hashes. SQLite WAL participates in snapshot identity and
  verification; changed files get a distinct snapshot. Concurrent case writes in one runtime are
  serialized. Explicit case IDs are preserved even when their display names differ.
- Keyword and vector retrieval filter by case before limiting results. Document provenance reaches
  chunks. Source bytes are checked both before model input and before displaying generated claims.
- Event XML records and native Windows EVTX/hive readers preserve observed values. Chrome visit
  timestamps are individual visits. Registry key last-write time is explicitly not execution time.
- Sysmon 3/11/13 records can produce process/network/file/registry relationships with record and source
  references. Generic entity co-occurrence remains MENTIONS, not a claimed causal connection.
- Background status is persisted and shown in WebUI. Previously running records become interrupted
  after restart. One runtime per workspace is supported; automatic resume/process leases are not added.
- ReportLab PDF resources and the new general report template are included in the Windows spec.
  The source CLI, package resource collection, PDF rendering and lint are checked; an EXE rebuild
  and live LLM/EVTX/hive evaluation are not part of the completed checks.
- Model and embedding evidence destinations are limited to loopback, with local tools only in case
  mode. Remote memory consolidation is blocked. This is not an operating-system network sandbox.
- Parser limits remain: 256 MiB default file size, 10,000 Chrome/event/hive records, hive depth 64.
  Report retrieval uses six hits/query, 600 characters/hit and an 8,000-character section context.
  These are bounded observations, not a complete device examination or a malware verdict.
- HTML/PDF share the checked report and audit decisions. Rendering happens before replacing output
  files; each replacement is atomic. The four-format publication is not a filesystem transaction.
- Old unscoped/malformed evidence is excluded instead of silently migrated or upgraded. Re-ingest it
  in the selected case. Recorded hashes are local acquisition baselines, not a signed custody log.

Verification uses real temporary files/SQLite, model/process-boundary fakes and Hypothesis schema
properties. A synthetic Korean two-page report was rendered and visually inspected, including tables,
long paths and footers. No numeric hallucination reduction/accuracy claim is made.

Final checks (2026-10-10): `py -3.12 -m pytest tests -q` — 571 passed;
`py -3.12 -m ruff check forensic_claw tests` — passed;
`node --check forensic_claw/webui/static/app.js` — passed;
`py -3.12 -m forensic_claw --help` — passed; `git diff --check` — passed.

### WebUI follow-up (2026-10-10)

- Case navigation stays visible; chat, evidence/records and reports have separate keyboard-accessible
  tabs. Source and evidence details show human-readable fields with raw metadata collapsed.
- New case creation preserves existing cases; file selection and drag/drop ingest into the selected
  case ID. Case and attachment changes are blocked while a request or upload is running.
- Source selection opens details; analysis remains case-wide. Opening records/report tabs refreshes
  current integrity. Report previews render accessible escaped Markdown tables and list only
  formats actually on disk. Report generation has a visible stop control.
- Attachment metadata no longer displaces the actual user question in case retrieval.
- Plain-text executable references no longer receive duplicate Domain classifications; existing
  executable detection is reused. A real-file/SQLite Hypothesis regression protects the rule.
  Previously saved case graphs are not automatically rewritten.
- Local browser QA used synthetic files and the real channel/agent/storage/export pipeline with
  only model responses replaced at the boundary. Initial setup, new case, file selection, scoped
  case analysis, report creation, PDF download and source details passed. Desktop 1280x900 and
  mobile 390x844 layouts were inspected; no page-wide horizontal overflow or console errors found.
- `node --test tests/webui/markdown.test.cjs` — 3 passed (tables, escaping, code-block isolation).
  Developer architecture PNG/SVG and screenshots are separate local deliverables, not UI assets.
  Live model quality, a rebuilt executable and large real-case performance remain unchecked.

### Live model evaluation and Windows release (2026-10-10)

- Added `evaluate-model` to both Python CLI and EXE. It reads Pi models/settings without exporting
  credentials or endpoint URLs. Twenty synthetic questions and handwritten ground truth measure
  extraction, citations, requested values, abstention and one injected instruction. The benchmark
  JSON includes questions, expected facts, raw answers, checks and generation settings.
- Baseline: 20 questions x 3 repetitions, temperature 0, max_tokens 2048, timeout 90 seconds.
  Question accuracy 59/60 (98.3%); the remaining request timed out and remains in the denominator.
  Completed responses were correct 59/59. Grounded claims 52/52; answerable-question coverage 41/42;
  abstention 18/18; no unsupported claims survived the gate. Integrity/provenance fault replay
  blocked 205/205 modified inputs. Repetitions are correlated; these are descriptive fixture scores.
- Configured model `empero-ai/Qwen3.8-27B-Ridge-GGUF` differs from the server-returned identity
  `augustine223/Huihui-Qwen3.8-27B-abliterated-KO-i1-Ridge`. This is server metadata, not an independent
  verification of model weights. The alternative localhost provider was offline. The selected server
  is non-loopback: only synthetic benchmark inputs were sent; real-case analysis remains blocked.
- An injected instruction can contain text that passes a substring/citation gate. The independent
  oracle explicitly excludes instruction text and reports it as wrong even if the gate accepts it.
  Passing this benchmark is not proof of general hallucination resistance or real-case accuracy.
- EXE smoke uncovered a report-scope regression when a selected case number differed from its
  display name. `/report` now preserves the selected ID when materializing its manifest; a real
  file/SQLite/report regression protects it.
- Final source checks: pytest 580 passed, Ruff passed, Node renderer 3 passed, diff check passed.
  A clean Python environment built Windows x64 v0.3.0 with PyInstaller. Frozen CLI, WebUI resources,
  case creation/upload, checked chat and HTML/PDF/audit downloads passed. Frozen workflow smoke
  replaces only the HTTP model boundary; its two-page PDF was rendered and visually inspected.
  Frozen EXE live-model evaluation additionally passed 20/20 questions with zero API errors.
  This separate validation run does not replace or inflate the 59/60 baseline above.
  Native parser accuracy, large real cases and Windows code signing remain outside these checks.
