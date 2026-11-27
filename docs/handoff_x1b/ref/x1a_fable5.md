# Code review r4b (closing): X-1a (250a858 on feature/x1-producer-evidence) -- Fable 5.2 (2026-11-27)

Scope: `git show HEAD` in `.census6/wt_x1`, the Python part only
(`src/tdo_v2/integration/configured_bundle.py`). Read-only; I ran nothing and did not read the Java diff, the
test or the docs table.

**Verdict: APPROVE.** No P1, no P2 from me.

## 1. My r4 P2-1

Closed. `_verify_profile_evidence` keeps one descriptor per touched member in `descriptors`, reads every row
slice and the original's headers through it, and closes them all in a `finally`
(`src/tdo_v2/integration/configured_bundle.py:410-416`, `:428-429`, `:447-449`). The hashing rule (`hashed` /
`checked`) is unchanged, and a failed admission does not leak descriptors.

## 2. Astra's open P2 (unbounded descriptor map, EMFILE) -- deferring to X-1b

I agree with deferring it.

* The map holds one descriptor per block member that an exported instruction row touches, plus the original.
  Block members are the image's memory blocks with bytes; an image needs more than about a thousand
  instruction-bearing blocks to reach the limit. None of the gate images or ntdll is near that.
* When it does happen it fails closed: the open raises, the `finally` closes what was opened, and the Bundle is
  not admitted. No wrong fact can come of it.
* The fix (a bounded cache with eviction) changes the same code the X-1b admission time / peak measurement
  will exercise, so doing both together is the cheaper order.

One condition: write it into the X-1b scope as an item, with the measurement.

## 3. P3

* P3-1. The EMFILE case surfaces as a bare `OSError`, not a `BundleAdmissionError`: the `except` clause at
  `:445` lists only evidence and parsing errors. When the bounded cache lands in X-1b, convert it so the caller
  sees an admission refusal with a reason.
* P3-2. Carried, unchanged: observations hashed twice on the frozen path; `json.loads` beside the strict raw
  parser.

Verdict: **APPROVE**, with the descriptor bound and the admission measurement recorded for X-1b. Not seen by
me: the Java change, the gate result, the measurement table.
