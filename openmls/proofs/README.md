# OpenMLS — formal verification

Verifying parts of [OpenMLS](https://github.com/openmls/openmls) (RFC 9420) by extracting
Rust to Lean: `hax_lib` contracts on the Rust source, extraction via
[Charon](https://github.com/AeneasVerif/charon)/[Aeneas](https://github.com/AeneasVerif/aeneas),
core-library models from [Hax](https://github.com/cryspen/hax), proofs in Lean 4.

## Progress

** ratchet-tree math (`treemath`). *Complete.***

- Function contracts (pre/post-conditions) live directly in the Rust source
  (`openmls/src/binary_tree/array_representation/treemath.rs`) and travel through
  extraction.
- All proof obligations — panic-freedom plus the functional postconditions — are
  proved in [`lean/`](lean/). The trusted surface is empty: no admitted
  contracts, no axioms beyond Lean's three standard ones (`propext`,
  `Classical.choice`, `Quot.sound`); the correspondence between the proved
  theorems and the generated specifications is machine-checked
  (`lean/Openmls/Proofs/Verification.lean`).
- See [`lean/README.org`](lean/README.org) for the obligation table, module layout, and
  proof scheme.
