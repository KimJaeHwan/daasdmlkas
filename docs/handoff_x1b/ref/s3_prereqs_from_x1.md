# S3 merge prerequisites carried from X-1a (Fable X-1a r1 P2-2, Astra X-1a r1 closing note)

X-1a implemented the s3-on evidence, the verified admission, the one reader (`stack_evidence.authority`) and the
template check (`summary_templates.refusal(policy=..., stack_authority=...)`), but no production caller passes
`s3-on` before S3. These items land WITH S3's first s3-on caller, in the same merge -- they are prerequisites,
not follow-ups:

1. **Run-wide image inventory.** An s3-on run resolves an authority result for the main image and every
   participating linked image BEFORE any dependent fact is derived or reused, through `authority(...,
   policy="s3-on", images=<every participating image>, seals=<each image's verified Bundle seal>,
   coverage=<each image's Coverage bound to that seal>)`. `authority` fails closed without the inventory.
2. **Linker lookup order and cache key (r4 4.5 item 5).** Under s3-on the library's Bundle is admitted (its
   evidence verified) BEFORE the template cache lookup (`linking.py` around the `cache.lookup` at ~:406, the
   library Bundle opened today only at ~:479); one verified library Bundle object serves lookup and derivation;
   the cache key adds the seal id, evidence digest, policy and coverage decision.
3. **Template application.** Every template application in an s3-on run passes `policy="s3-on"` and the
   `stack_authority` (seal, evidence digest, policy, coverage) of the template's library; the derivation
   records the same `stack_authority` in the template source (`summary_store` already accepts the key).
4. **Acceptance test (Astra X-1 r3 A3-4):** a clean main image and two DLLs; make one DLL unavailable, then dirty:
   main and sibling dependent facts lose `globals-disjoint-from-stack` in cold and warm runs; direct template
   application rejects stale authority; an unchanged verified Bundle still permits a warm hit.
5. **UE template (r4 4.7):** an s3-on run cannot use the shipped template (v3 evidence) until an s3-on derivation
   with real S3 coverage exists; "S3 ON by default" is measured only after that template is applied at the UE
   import.
6. **Unbounded transfers (r4 4.8, Fable X-1a r1 P2-3):** the owner chooses, from the X-1a measurement
   (`.census6/x1_measure.sh`, docs 25.121), between UNCHECKED and the "every instruction start a destination"
   fallback reading for indirect jumps with no listed destination, before S3 turns s3-on on by default.
7. **UD2 (r4 4.8):** if UD2 rows alone withdraw the verdict on ordinary binaries, the owner decides between the
   F1-discharge requirement and a fault class under a named premise.
8. **Attestation is per process (Fable X-1a r3 P3).** The verified stack evidence carries an HMAC under a key made
   once per process; a verified object is never persisted or passed between processes. A worker or a resumed run
   re-admits the Bundle (verification again) -- S3's caller must not cache a verified object across processes.
9. **UE note (Fable X-1a r3 P3).** Under the X-1a measurement both UE DLLs are dirty under either reading of
   unbounded transfers (debuggame: unbounded 1, trap 95; development: unbounded 2, trap 99) -- item 6 decides
   what S3 does with them; their traps need S3's OS-contract model before they can be covered.
10. **Producer trust stays with TBR (owner 2026-11-27).** Kernel-row lift shapes and listing stability during export
    are [TBR-G1-decode] / [TBR-G2-lifter] / [TBR-G3-scan]; S3 reads TBR's G1 syscall / int-2E pins through the G1
    reader instead of widening the Java checks.
