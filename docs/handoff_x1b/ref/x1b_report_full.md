| pair | stage 0 members | stage 0 default / legacy | s1+fte | s1+fte+len | s1+fte+len+proof | reg | len | x1+len | proof effect | old vs published | interaction (default) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| KernelBase#1c1aeb843abd | = | = / skip | d:12 sections differ / = ; l:skip | d:12 sections differ / = ; l:skip | d:12 sections differ / = ; l:skip | d:= / = ; l:skip | d:12 sections differ / = ; l:skip | d:12 sections differ / = ; l:skip | d:12 sections differ / = ; l:skip | d:12 sections differ / = ; l:skip | = |
| corpus/clang-x64-O0#dff1d959f108 | = | = / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:= / = ; l:= / = | d:20 sections differ / = ; l:20 sections differ / = | = |
| corpus/clang-x64-O2#5b842e47c166 | = | = / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:= / = ; l:= / = | d:20 sections differ / = ; l:20 sections differ / = | = |
| corpus/clang-x64-O3#18a0cb4b245f | = | = / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:= / = ; l:= / = | d:20 sections differ / = ; l:20 sections differ / = | = |
| corpus/clang-x86-O0#a12d358d17eb | = | = / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:= / = ; l:= / = | d:20 sections differ / = ; l:20 sections differ / = | = |
| corpus/clang-x86-O2#cac9df5173a5 | = | = / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:= / = ; l:= / = | d:20 sections differ / = ; l:20 sections differ / = | = |
| corpus/gcc-x64-O2-rep#d6beeeda363e | 1 attributed | = / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | = |
| corpus/gcc-x64-O3#26f77b2da053 | 1 attributed | = / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | d:20 sections differ / = ; l:20 sections differ / = | = |
| kernel32#fb2e9de1eb08 | = | = / skip | d:13 sections differ / = ; l:skip | d:13 sections differ / = ; l:skip | d:13 sections differ / = ; l:skip | d:= / = ; l:skip | d:13 sections differ / = ; l:skip | d:13 sections differ / = ; l:skip | d:9 sections differ / = ; l:skip | d:13 sections differ / = ; l:skip | = |
| ntdll#e99c2b4a4da6 | **4220 unexplained** | **DIFF** / skip | d:missing ; l:skip | d:missing ; l:skip | d:missing ; l:skip | d:missing ; l:skip | d:missing ; l:skip | d:missing ; l:skip | d:missing ; l:skip | d:missing ; l:skip | missing |
| ntdll_small#3a3df42098cd | = | **DIFF** / skip | d:missing ; l:skip | d:missing ; l:skip | d:missing ; l:skip | d:missing ; l:skip | d:missing ; l:skip | d:missing ; l:skip | d:missing ; l:skip | d:missing ; l:skip | missing |
Traceback (most recent call last):
  File "/mnt/d/01_gitproject/14_TDO_v2/daasdmlkas/.census6/x1b_report.py", line 130, in <module>
    raise SystemExit(main())
                     ~~~~^^
  File "/mnt/d/01_gitproject/14_TDO_v2/daasdmlkas/.census6/x1b_report.py", line 100, in main
    inter = "-" if args.no_interaction else interaction(work, "default", project_document)
                                            ~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/mnt/d/01_gitproject/14_TDO_v2/daasdmlkas/.census6/x1b_report.py", line 53, in interaction
    digests = {name: projected_sections(path, project) for name, path in files.items()}
                     ~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^
  File "/mnt/d/01_gitproject/14_TDO_v2/daasdmlkas/.census6/x1b_report.py", line 46, in projected_sections
    return project(json.load(handle))["digests"]
           ~~~~~~~^^^^^^^^^^^^^^^^^^^
  File "/mnt/d/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_x1b/tools/graph_fidelity/paired_projection.py", line 522, in project_document
    tokens = build_tokens(document)
  File "/mnt/d/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_x1b/tools/graph_fidelity/paired_projection.py", line 130, in build_tokens
    raise Ambiguous("two address atoms share one label")
paired_projection.Ambiguous: two address atoms share one label
