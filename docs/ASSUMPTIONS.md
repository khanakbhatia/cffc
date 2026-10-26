# Concretizations and assumptions made during implementation

Stage 3.5 left a handful of points as explicit design decisions ("[CONCRETIZATION]") or did not
reach yet (no Stage 3.3 was supplied to this implementer). Each is recorded here with its rationale
so Thirzah/Disha can check it against the architecture doc and the paper text.

**A1 - 16 vs 14 canonical fields.** Stage 3.5 §E's formula divides by "N × 16 (16 named fields in the
schema, Stage 3.3 §1)", but Stage 3.3 was not available to this implementer. Stage 2 §13 lists 14
fields and Stage 2 §14 separately requires `schema_version` (for safe schema evolution) and a
`provider_specific` catch-all (so provider-specific forensic detail is never discarded). 14 + 2 = 16,
consistent with Stage 3.5's divisor. If Stage 3.3 defined a different 16, `CANONICAL_FIELDS` in
`schema.py` is the single place to reconcile it.

**A2 - "populated".** A field counts as populated if it is not `None` and not an empty string, dict,
or list. The `"unknown"` principal sentinel is a real (if low-information) string and counts as
populated, per Stage 3.5 §E's note "populated with 'unknown' sentinel counts as populated".

**A3 - AND-mode semantics.** Stage 2 §16 says AND requires "all" keys to match but does not say what
happens when a key is null on one side (e.g. no `resource_id` recorded). Concretization: AND links two
events if (a) at least `and_min_comparable_keys` (default 2) keys are non-null on **both** events, and
(b) every one of those comparable keys is equal. A null key is simply not compared - it does not block
a link by itself, but a single comparable key is not enough to call it "AND of multiple conditions".
This is the "AND-mode semantics concretization" flagged in Stage 3.5 Part F.

**A4 - ground-truth-to-event matching with more than one candidate.** Stage 3.5 §F defines the match
rule (`action` equal AND |Δt| ≤ tolerance) but not what happens with multiple qualifying candidates.
Concretization (`matching.py`): build all qualifying (ground-truth step, candidate) edges, prefer edges
with fewer identity mismatches (against `expected_principal`/`expected_source_ip` when given) then
smaller |Δt|, and assign greedily so each candidate is used by at most one step. Steps with more than
one qualifying candidate are flagged `ambiguous_steps` for manual review rather than silently resolved.

**A5 - pair-counting scope for precision/recall.** Stage 3.5 §G/§H count "event pairs"; it does not
say how to treat algorithm-grouped events that have no ground-truth label (e.g. benign noise events
the correlation algorithm happens to link to a labelled event). Three scopes are implemented
(`metrics.PAIR_SCOPES`): `labeled_vs_unlabeled` (default - an unlabeled event linked to a labeled one
is a false positive; two unlabeled events linked to each other carry no ground-truth claim and are
excluded), `labeled_only` (restrict to pairs where both events are ground-truth steps - a stricter,
"how well did we link the steps we know about" reading), and `all` (every unlabeled event treated as
its own singleton truth group, so any merge involving it is penalized). The default is documented in
`configs/default.toml`; the experiment runner reports all three under `details.pair_metrics_by_scope`
so the team can pick the one that matches the paper's intended claim.

**A6 - same-second timestamp ties.** CloudTrail `eventTime` has 1-second granularity. Stage 2 §17 says
to break ties "using the provider's own ordering hint... where available" but CloudTrail does not
publish an authoritative intra-second sequence number, and delivery order inside a log file is not
guaranteed to be causal (Stage 3.5's own SoK citation, Stage 1 item 16). Concretization: ties are
broken by `(source_log_file, position within file, event_id)` - deterministic and reproducible, but
**not a claim that this is the true causal order**. `CanonicalEvent.sort_key` is the single place this
is implemented; `timeline_ordering_accuracy`'s `misordered_adjacent_pairs` output is exactly the set of
ground-truth-adjacent steps this limitation can affect, and the synthetic scenario A deliberately
includes one same-second collision (steps 3-4) so the limitation is visible in `outputs/synthetic/`
rather than asserted only in prose.

**A7 - F1 when precision and recall are both defined and zero.** Stage 3.5 §I's zero-division guard
only covers "both P and R undefined". When both are defined and exactly zero (e.g. every linked pair
is wrong and every true pair was missed), the harmonic-mean formula is `0/0`. Convention: report
`F1 = 0.0` in that case (not `null`), since both inputs are legitimately measured zeros, not undefined
quantities. Covered by `test_f1_zero_when_p_and_r_zero`.

**A8 - evidence_hash on unmanifested files.** The integrity gate (Stage 3.5 §A.5) is strict by default:
any manifest/file mismatch, including a raw file present but not yet in the manifest, blocks ingestion
(`strict_integrity=True`). A non-strict mode exists (used only for inspecting a broken state, e.g. in
tests) that falls back to hashing the file in place for `evidence_hash`, which is **not** a recorded
collection-time hash and must never be reported as such in results.
