# Frozen V1.8 explicit-flow fixtures

`manifest.json` pins SHA-256, case count, seed and holdout rules. All source values
are fabricated. Contracts and wire payloads were frozen before integration and
are not generated from the scanner or taint implementation.

Development is the only debugging/tuning split. Holdout is an authored unused
split, not a blind third-party benchmark. Do not execute it until the candidate
implementation is committed; do not adjust code on its results and keep calling
it independent. Unsupported transformations have no expected wire output and
must be UNRUN in every arm. The common transport canary intentionally disables
enforcement identically in all arms, is a measurement control, and is excluded
from classification metrics.

Do not edit inputs or expected answers to make an arm pass. Append a new version
and preserve this one when future experiments require changed contracts.
