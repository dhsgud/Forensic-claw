# Next evidence recommendation

Forensic-Claw ranks analyst-defined, read-only checks under a remaining budget. The example asks whether a download in the target profile came from origin A. Each hypothesis predicts one outcome for each check. A result of `inconsistent` means every registered hypothesis conflicts with at least one observation.

```powershell
py -3.12 -m forensic_claw next-evidence research/next_evidence/browser-case-model.json --budget 3
py -3.12 -m forensic_claw next-evidence research/next_evidence/browser-case-model.json --budget 2 --observed profile=target
```

Report costs in comparable positive integer units. An observed value that no remaining hypothesis predicts makes the model inconsistent. When the tool returns `abstain` without a recommendation, the modeled checks cannot resolve a verdict within the remaining budget. Projected resolution counts assume equal weights on the registered hypotheses and describe the case model.

## Reproduce the evaluation

On 2026-11-26 UTC, Playwright CLI 0.1.25 captured 24 downloads per browser on Windows 11 build 26300. `browser-records.json` contains the Microsoft Edge 158.0.4370.33 records, and `chrome-records.json` contains the Google Chrome 157.0.8103.79 records. The browser profiles are temporary. The capture script starts three loopback HTTP listeners, sends an identical harmless text attachment from two origins, and reads the temporary browser History SQLite database after each profile closes. The shipped rows retain a profile alias, download row ID, state, byte count, digest, redirect category, terminal origin and server observation.

From the repository root with project dependencies installed:

```powershell
py -3.12 -m research.next_evidence.capture_browser edge-replication.json --browser msedge --rounds 3
py -3.12 -m research.next_evidence.capture_browser chrome-replication.json --browser chrome --rounds 3
py -3.12 -m research.next_evidence.benchmark research/next_evidence/browser-records.json edge-comparison-replication.json
py -3.12 -m research.next_evidence.benchmark research/next_evidence/chrome-records.json chrome-comparison-replication.json
py -3.12 -m research.next_evidence.pi_baseline research/next_evidence/chrome-records.json chrome-pi-replication.json --recorded research/next_evidence/pi-results.json
py -3.12 -m research.next_evidence.pi_baseline research/next_evidence/browser-records.json pi-replication.json
```

Browser capture requires the selected browser, Node.js and npm. The Pi experiment requires the [NVIDIA QAD checkpoint](https://huggingface.co/nvidia/Qwen3.8-Flash-Next-NVFP4-QAD) `nvidia/Qwen3.8-Flash-Next-NVFP4-QAD`, configured in Pi under the alias `llamacpp/coder390`. The deterministic replay uses the captured rows as an observation oracle, with explicitly modeled query costs and availability. The first batch tunes the fixed order. The last two batches repeat the acquisition on new profiles. The replay evaluates two predicates over the same acquired records and does not measure wall-clock acquisition or field performance. Pi generates a contingent policy without access to held-out outcomes, then uses the same verdict checker as the four deterministic methods. In the standard scenario the recorded response mixed prose with a single valid JSON block. The strict result is retained and replay of that block is stored separately as `recovered_rows`.

`results.json` contains counts, per-trial outcomes and the query sequence. Run `py -3.12 -m research.next_evidence.plot_results` with Matplotlib installed to regenerate the manuscript figure from those results.

Each browser has 1,280 policy replay rows. `chrome-results.json` reproduces the Edge results in `results.json`; the normalized observation rows match across browsers. `chrome-pi-replay.json` applies the previously recorded responses to the Chrome holdout without calling the model again.


## Direct SQL baseline

A specific completed download can be looked up in an acquired Edge or Chrome History database with:

```powershell
py -3.12 -m forensic_claw download-source 'C:/Evidence/History' 7
```

The row identifier is local to the database. The verification capture uses two fresh batches per browser, reverses the order of downloads in the comparison profile, and compares the direct SQL result with the separately extracted final URL and the responding server. It records only normalized outcomes and query durations. For the comparison, the same captured outcomes are exposed under four evidence-availability conditions. The acquisition manifest is controlled ground-truth profile linkage supplied as an extra observation; the recorded query time measures the local connection and SQL call, without acquisition or analyst time.

```powershell
py -3.12 -m research.next_evidence.capture_browser edge-direct-replication.json --browser msedge --rounds 2 --verify-direct
py -3.12 -m research.next_evidence.capture_browser chrome-direct-replication.json --browser chrome --rounds 2 --verify-direct
py -3.12 -m research.next_evidence.direct_baseline research/next_evidence/msedge-direct-records.json edge-direct-result-replication.json
py -3.12 -m research.next_evidence.direct_baseline research/next_evidence/chrome-direct-records.json chrome-direct-result-replication.json
```
