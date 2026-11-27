# X-1b paired comparison tools

Design: docs 25.122 (X-1b) and `design_x1b_method_r3` (method). Run in WSL (`~/venvs/tdo/bin/python`, `python3`).

| Tool | Purpose |
|---|---|
| `x1b_reexport.py <tree>` | replay every old export (`<old>/**/*.logs/*.command.json`) with a tree's exporter, fresh ids, verify, record `x1b_pairs.json`; `--no-s1-prescript` = attribution evidence |
| `x1b_bundle_tools.py verify / derive / strip / members` | raw verification; comparison copy with the old id; strip additions relative to one old input (declared re-binding only); member-by-member comparison |
| `x1b_stages.py <tree> <pairs> <key>` | stage 0 + stage 1 for one pair: copies, paired dumps (`semantic_snapshot dump --paired-sections`), strict + projected comparisons -> `<out>/<key>/result.json`; `--compare-only` reuses dumps |
| `x1b_stages_all.sh <names>` | the stages for several pairs (`JOBS`, `CONFIGS`, `COMPARE_ONLY`, `PAIRS`) |
| `x1b_report.py` | markdown table of every `result.json` + interaction sets |
| `x1b_projdev.py <a.json.gz> <b.json.gz>` | development: project two snapshots, print residual differences by path pattern |
| `x1b_ue_template.py <published UE producer gen> <out>` | UE migration outputs: v3 vs v5 switch lists, template re-derived under s3-off |
| `DumpExports.java` | Ghidra script: external entry point symbols (attribution evidence) |

The projection itself is `tools/graph_fidelity/paired_projection.py` (tests: `tests/intra/test_x1b_paired_projection.py`).
