# Next evidence recommendation

Forensic-Claw ranks analyst-defined, read-only checks under a remaining budget. The example asks whether a download in the target profile came from origin A. Each hypothesis predicts one outcome for each check. A result of `inconsistent` means every registered hypothesis conflicts with at least one observation.

```powershell
py -3.12 -m forensic_claw next-evidence research/next_evidence/browser-case-model.json --budget 3
py -3.12 -m forensic_claw next-evidence research/next_evidence/browser-case-model.json --budget 2 --observed profile=target
```

Report costs in comparable positive integer units. An observed value that no remaining hypothesis predicts makes the model inconsistent. When the tool returns `abstain` without a recommendation, the modeled checks cannot resolve a verdict within the remaining budget. Projected resolution counts assume equal weights on the registered hypotheses and describe the case model.

## Reproduce the evaluation

The normalized rows in `browser-records.json` were captured on Windows 11 build 26300 with Edge 158.0.4370.33 and Playwright CLI 0.1.25 on 2026-11-26 UTC. The browser profiles are temporary. The capture script starts three loopback HTTP listeners, sends an identical harmless text attachment from two origins, and reads the temporary Edge History SQLite database after each profile closes. The shipped rows retain a profile alias, download row ID, state, byte count, digest, redirect category, terminal origin and server observation.

From the repository root with project dependencies installed:

```powershell
py -3.12 research/next_evidence/capture_browser.py browser-replication.json --rounds 3
py -3.12 -m research.next_evidence.benchmark research/next_evidence/browser-records.json comparison-replication.json
py -3.12 -m research.next_evidence.pi_baseline research/next_evidence/browser-records.json pi-replication.json
```

Browser capture requires Edge, Node.js and npm. The Pi experiment requires the [NVIDIA QAD checkpoint](https://huggingface.co/nvidia/Qwen3.8-Flash-Next-NVFP4-QAD) `nvidia/Qwen3.8-Flash-Next-NVFP4-QAD`, configured in Pi under the alias `llamacpp/coder390`. The deterministic replay uses the captured rows as an observation oracle, with explicitly modeled query costs and availability. The first batch tunes the fixed order. The last two batches repeat the acquisition on new profiles. The replay evaluates two predicates over the same acquired records and does not measure wall-clock acquisition or field performance. Pi generates a contingent policy without access to held-out outcomes, then uses the same verdict checker as the four deterministic methods. In the standard scenario the recorded response mixed prose with a single valid JSON block. The strict result is retained and replay of that block is stored separately as `recovered_rows`.

`results.json` contains counts, per-trial outcomes and the query sequence. Run `py -3.12 -m research.next_evidence.plot_results` with Matplotlib installed to regenerate the manuscript figure from those results.
