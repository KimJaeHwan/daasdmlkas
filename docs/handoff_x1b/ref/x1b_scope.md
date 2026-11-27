# X-1b scope (carried from the X-1a closing rounds)

1. Re-export (gate Bundles, ntdll closure, field cases, UE producer bundle) with row lengths + the original image;
   paired-generation comparison; new gate baseline. Tell TBR first (they run decode_check --producer-override on
   one Bundle per kind).
2. Admission time / peak on the largest profiled image (Fable X-1a r1/r4).
3. [ASTRA-OPEN] P2 (Astra x1a_astra5.md): the per-admission descriptor map in
   configured_bundle._verify_profile_evidence is unbounded -> EMFILE at >1024 touched block members (format allows
   65,536 blocks). Bound the cache, close on eviction; Fable P3: raise BundleAdmissionError, not a bare OSError.
   Test: many block members under a low RLIMIT_NOFILE.
4. Fable P3s carried: observations hashed twice on the frozen path; json.loads beside the strict raw parser.
