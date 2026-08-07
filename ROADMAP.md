# Artifact-Pulse — Industry Readiness Roadmap

> Honest gap analysis: where Artifact-Pulse stands against KAPE, Velociraptor, Cyber Triage, and DFIR ORC — and the prioritized work to close the gaps.
>
> **Verdict: not yet industry-accurate.** It is a genuine triage tool with real architecture (layered extraction, chain-of-custody hashing, ML anomaly scoring, web UI), but it is a learning/lab-grade tool today. The gaps below are the path to credibility.

---

## 1. Comparison snapshot

| Capability | Artifact-Pulse | KAPE | Velociraptor | Cyber Triage | DFIR ORC |
|---|---|---|---|---|---|
| Artifact breadth | ~4 layers (FS, EVTX, processes, registry) | **~100+ module targets** (MFT, USN, Prefetch, ShimCache, Amcache, LNK, browsers…) | **300+ VQL artifacts** | Targeted triage set | Config-driven, ~40 collectors |
| Collection model | Local only, in-memory | Local, CLI/batch | **Agent + fleet (thousands of hosts)** | Local agentless | **Remote via AD/GPO at org scale** |
| Timeline analysis | ❌ none | ⚠️ (outputs feed timeline tools) | ✅ (super-timelines, hunt) | ✅ | ⚠️ (raw; feeds Hayabusa etc.) |
| YARA / malware detection | ❌ | ✅ (via modules) | ✅ (VQL YARA) | ✅ (scoring engine) | ⚠️ (post-processing) |
| Evidence integrity | ✅ content/chain hashes (concept good) | ✅ | ✅ | ✅ | ✅ **collection-level hash + signature** |
| Query language | ❌ (fixed endpoints) | ⚠️ (CLI flags) | ✅ **VQL** | ⚠️ | ⚠️ (config files) |
| Automated scoring | ✅ ML anomaly scoring (unique edge) | ❌ | ⚠️ | ✅ (threat scoring) | ❌ |
| Report generation | ✅ PDF | ⚠️ | ✅ | ✅ | ❌ |
| Court-ready / admissible | ❌ (no methodology doc, tool versioning, audit trail) | ✅ (mature) | ✅ | ✅ | ✅ |

## 2. The six hard gaps

1. **Collection breadth is ~2% of KAPE.** Filesystem walk + EVTX + registry + processes is a start, but the forensic gold is missing: $MFT/$J (NTFS journal), Prefetch, ShimCache, Amcache, LNK/Jump Lists, browser history, scheduled tasks, services, network config, memory. **Without MFT + Prefetch + Amcache you cannot reconstruct "what ran when"** — the core of DFIR.

2. **No timeline.** DFIR is fundamentally timeline work (Plaso / Timeline Explorer style). Artifact-Pulse has no super-timeline view, no bodyfile output, nothing that feeds `mactime` / Timeline Explorer. This is the single biggest functional gap.

3. **No evidence-grade integrity.** Artifact hashing exists, but there is no acquisition-time collection hash of the whole package, no signed seal, no tool-version + methodology documentation, no verification workflow that would survive scrutiny. DFIR ORC's entire design is this.

4. **No YARA and no known-bad matching.** Industry triage flags malware with YARA rules + known-hash lookups (NSRL known-good, VirusTotal, Malpedia). The ML scoring is conceptually *ahead* of most tools, but it is a statistical signal, not evidence.

5. **No scale / no agent model.** Single host, single process, in-memory. KAPE is batchable, Velociraptor hunts fleets, DFIR ORC collects org-wide via AD. Lab-grade, not IR-engagement-grade.

6. **No query layer.** VQL is what makes Velociraptor powerful — arbitrary cross-host artifact queries. Artifact-Pulse exposes 11 fixed endpoints. An analyst cannot ask "all EXE files modified 02:00–04:00 across hosts."

## 3. Prioritized roadmap

### Tier 1 — credible triage tool (do first)
- [x] **Bug fix: `app.run(threaded=True)`** — API freezes during pipeline runs (single-threaded server); status polling / pages stall until extraction finishes.
- [ ] **$MFT + USN Journal parsing** (via `pytsk3` / `dissect`, or by invoking KAPE as the collector) — unlocks timeline reconstruction.
- [ ] **Timeline view**: normalize all artifacts to a common timeline, bodyfile/Plaso-compatible output, timeline page in the UI.
- [ ] **YARA scanning** on collected files (open-source rule packs).

### Tier 2 — evidence-grade
- [ ] **Collection package**: zip + SHA-256 of everything + signed seal (extend `EvidenceSealer` to the whole package).
- [ ] **Known-good/known-bad hash matching** (NSRL / VirusTotal / Malpedia lookups).
- [ ] **Court-readiness in reports**: methodology, tool versions, hash manifest in the PDF.

### Tier 3 — industry scale
- [ ] **Velociraptor integration**: ship Artifact-Pulse as a VQL artifact collector → inherits fleet + query capability.
- [ ] **Memory acquisition** (winpmem / Volatility 3) — zero memory analysis today.
- [ ] **Query layer / advanced filtering** over the artifact store.

## 4. Keep, don't change

- **ML anomaly scoring** — the ensemble + explanation approach is a genuine differentiator.
- **Chain-of-custody concept** — right idea, extend it package-wide (Tier 2).
- **Flask + React architecture** — clean separation, good foundation for the additions above.
