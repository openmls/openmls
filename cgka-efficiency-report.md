# MLS Efficiency: Reading Notes

Three papers on the communication complexity of Continuous Group-Key Agreement (CGKA),
with a focus on how the ratchet tree state affects commit cost in MLS.

## Papers

| File | Title | Authors | Year |
|------|-------|---------|------|
| `2025-1035.pdf` | Continuous Group-Key Agreement: Concurrent Updates without Pruning | Auerbach, Cueto Noval, Erol, Pietrzak | 2025 |
| `2024-1097.pdf` | The Cost of Maintaining Keys in Dynamic Groups with Applications to ME and Group Messaging | Anastos, Auerbach, Baig, Cueto Noval, Kwan, Pascual-Perez, Pietrzak | 2024 |
| `2023-1123.pdf` | On the Cost of Post-Compromise Security in Concurrent CGKA | Auerbach, Cueto Noval, Pascual-Perez, Pietrzak | 2023 |

---

## How Commit Size Depends on Tree State

The most direct analysis is in **2025-1035**, Sections 3–4.

### Blanks and the Resolution

The dominant cost of a commit is the `UpdPath` object: the committer must encrypt a fresh
seed to every node in the **resolution** of each co-path node (`2025-1035`, §2.2, §3).

The resolution `Res(v)` is the smallest covering of `v`'s subtree by non-blank nodes:
- **Populated node**: `Res(v) = {v}` — costs 1 ciphertext.
- **Blank internal node**: `Res(v) = Res(left(v)) ∪ Res(right(v))` — recurse into both children.

A blank co-path node therefore at least doubles the ciphertexts required at that level, and a
chain of blank ancestors turns a single co-path slot into an exponentially large set of
leaf-level encryptions. The commit cost is lower-bounded by (`2025-1035`, §4, p. 15):

```
Cost(t) ≥ Σ_{v ∈ co-path(committer)} |Res(v)|
```

**Unmerged leaves** compound the problem: when a user is added, their leaf is appended to
`v.unm` for every node `v` on their path. The seed at each co-path step must be encrypted to
`Res(v_sib) ∪ v_sib.unm`, so pending adds also inflate commit size (`2025-1035`, §2.2,
§3, Figure 3).

### Why Blanks Accumulate: Markov Chain Analysis

`2025-1035` §4.2 (Lemma 4.1) models the blank/populated state of each internal node `v` as
a two-state Markov chain under the **Exp-Prop-Com** experiment: in every round, P proposers
and C committers are chosen uniformly at random.

Transition dynamics:
- **Populated → blank**: any proposer whose path includes `v` will blank it.
- **Blank → populated**: only a committer whose path includes `v` re-keys it.

The **stationary blank probability** for a deep node works out to (Lemma 4.1, Eq. 2–4):

```
Pr[v is blank] ≈ P / (P + C)   for nodes at large depth
```

Concrete values (C = 1):

| Proposals P | Blank probability |
|------------|-------------------|
| 0 | 0 (clean tree) |
| 1 | ≈ 1/2 |
| 2 | ≈ 2/3 |
| 5 | ≈ 5/6 |
| 10 | ≈ 10/11 |

Even the most benign realistic scenario — one proposal per commit — drives roughly **half of
all internal nodes** to be blank in steady state.

### Expected Commit Cost: Theorem 4.2

Because blank nodes force resolution into both children recursively, the expected commit cost
grows **super-logarithmically** in the group size N (`2025-1035`, §4.3, Theorem 4.2):

$$\mathbb{E}[\text{Cost}(t)] \geq \Omega\!\left(N^{\,\log_2\!\left(1 + \frac{P}{P+C}\right)}\right)$$

The exponent `e = log₂(1 + P/(P+C))` for C = 1:

| P | e | Cost grows as |
|---|---|---------------|
| 0 | 0 | log(N) ✓ |
| 1 | ≈ 0.58 | N^{0.58} |
| 2 | ≈ 0.74 | N^{0.74} |
| 5 | ≈ 0.87 | N^{0.87} |
| 10 | ≈ 0.93 | N^{0.93} |
| 50 | ≈ 0.99 | N^{0.99} |

For the special case P = C = 1 the paper gives a sharper explicit bound (`2025-1035`, §4.3,
p. 17):

$$\mathbb{E}[\text{Cost}(t)] \geq \frac{\log^2(N)}{4} - \frac{\log(N)}{4}$$

For MLS's target group size of N = 50,000: log²(N) ≈ 250, versus the ideal log(N) ≈ 16.
With 50 concurrent proposals per commit the cost is essentially linear in N.

---

## Blank Inner Nodes vs. Unmerged Leaves: What Makes Each a Problem

Both phenomena inflate the number of ciphertexts in a commit, but through different
mechanisms and with different severity. The relevant definitions are in `2025-1035` §2.2;
the cost expression that ties both together is in §4, p. 15:

```
Cost(t) ≥ Σ_{v ∈ co-path(committer)} |Res(v_sib) ∪ v_sib.unm|
```

### Blank inner nodes: multiplicative / recursive fan-out

A blank node has **no public key**. There is nothing to encrypt to, so the protocol must
recurse: `Res(v) = Res(left(v)) ∪ Res(right(v))`. Each blank level on the co-path at
minimum doubles the ciphertext count for that slot. A chain of k consecutive blank
ancestors turns one co-path slot into up to 2^k leaf-level encryptions.

This is the mechanism that makes the cost exponent in Theorem 4.2 super-logarithmic: the
expected resolution size grows exponentially in the expected number of consecutive blank
ancestors, which is itself a function of the stationary blank probability P/(P+C)
(`2025-1035`, §4.2–4.3).

Blank inner nodes arise from two operations (`2025-1035`, §3, `apply-props`, Figure 2):
- **Update proposals**: the proposer's filtered path to the root is blanked.
- **Removes**: the removed user's leaf and entire path are blanked.

In both cases the blank persists on the co-path of every future committer until a future
committer happens to have that node on their own update path and re-keys it.

### Unmerged leaves: additive overhead

An unmerged leaf at node `v` means a recently added user whose leaf key has been placed
in the tree, but whose path has not yet been re-keyed by anyone — so no internal node on
their path holds a fresh key derived from their leaf. As a result, encrypting to `v` alone
would exclude that user; the seed must also be encrypted individually to each unmerged
leaf (`2025-1035`, §2.2, §3, `rekey-path` Figure 3, line 09):

```
for w ∈ Res(v_sib) ∪ v_sib.unm:
    C_j ←∪ Pke.Enc(w.pk, s_j)
```

Unmerged leaves add a **flat, additive** cost: if a populated co-path node has m unmerged
leaves, the cost for that slot is 1 + m rather than 1. This does not recurse and does not
compound geometrically.

Unmerged leaves arise from **add proposals** (`apply-props`, Figure 2, lines 14–17): the
added user's public key is placed at the leftmost unpopulated leaf, and that leaf is
added to `v.unm` for every node `v` on its path. They are cleared only when a committer's
update path passes through the node, at which point `rekey-path` sets `v.unm ← ∅` for all
nodes on the committer's path (Figure 3, line 12–13).

### How they interact

The two phenomena are independent in origin but compound each other in the cost expression:

- A **populated node with unmerged leaves**: `Res(v) = {v}`, cost = 1 + |v.unm|. Bounded
  and additive.
- A **blank node with unmerged leaves in its subtree**: the resolution recurses into
  children, and each node reached by the recursion may itself have unmerged leaves,
  adding their count at every level of the recursion. Blank nodes make unmerged-leaf
  overhead worse by expanding the set of nodes that contribute it.
- Conversely, unmerged leaves are a symptom of the **same structural asymmetry** as blank
  nodes: the committer can only fully integrate (merge) users on their own update path.
  Users added to other parts of the tree remain unmerged — and their path nodes remain
  populated but with growing `unm` lists — until someone in their subtree commits.

**The key distinction in severity** is that blank nodes cause multiplicative, recursive
damage (each blank at depth d from a leaf can contribute up to 2^d extra ciphertexts),
while unmerged leaves are additive (each unmerged leaf contributes exactly 1 extra
ciphertext per co-path slot that has it). In practice, blank nodes are therefore the
dominant driver of the super-logarithmic cost growth characterized by Theorem 4.2; the
2025 paper's Markov chain analysis and lower bound proof focus entirely on blank node
accumulation (`2025-1035`, §4.2–4.3), with unmerged leaves treated as secondary
(`2025-1035`, §3, §B.1).

---

## Why a Clean Tree is Hard to Maintain

The root cause is a structural **asymmetry** in MLS's propose-and-commit paradigm
(`2025-1035`, §1.1, §3):

1. **Each proposal blanks O(log N) nodes** on the proposer's filtered path to the root
   (`apply-props`, Figure 2 in `2025-1035`).
2. **Each commit re-keys only the committer's O(log N) nodes** (`rekey-path`, Figure 3).
3. The committer **cannot re-key other proposers' blanked paths** without learning their
   secrets, which would violate the tree invariant.
4. Blanked paths from previous proposals therefore **persist** until those specific users
   themselves issue a commit and re-key their own path.

In the meantime every subsequent commit must route around those blanks by encrypting to
deeper descendants, paying a higher and higher cost. The tree drifts to the P/(P+C)
stationary blank density with no way for a single committer to clean it up.

The worst case — essentially the full tree going blank — gives Ω(N) cost, which BDR20
(cited in all three papers) showed is **inherent** for any CGKA scheme achieving fast PCS
from standard primitives.

---

## The Fix: MLS-Cutoff

`2025-1035` §5 proposes **MLS-Cutoff**, a variant that achieves O(log N) expected commit
cost for constant P, without changing MLS's security model or consistency mechanisms.

**Key idea**: stop the blanking operation `i_cut = log(log(N))` steps before the root.
With random proposers and committers, their paths merge with high probability within the
top log(log(N)) levels. If two proposers' paths collide *below* the cutoff, only the path
from the collision point upward is blanked (§5.1). This prevents the most damaging blanks
near the root while preserving PCS at the same speed as MLS.

**Result** (`2025-1035`, §5.3): for constant P proposals per commit and random operations,
MLS-Cutoff achieves expected commit size O(log N).

---

## The Other Two Papers

### 2023-1123: Lower Bounds for Concurrent PCS

Proves that CGKA protocols healing in k rounds must pay at least
~k · N^{1+1/k} / log(k) ciphertexts per update on average (`2023-1123`, §1.1, Table 1).
This shows CoCoA is near-optimal for logarithmic-round healing and motivates why one cannot
simply "fix" MLS's blank problem by moving to a concurrent scheme — there is a fundamental
cost floor.

### 2024-1097: Batched User Replacements

Proves a tight Ω(d · ln(n/d)) lower bound on the communication cost of replacing d users
in a group of size n (`2024-1097`, §1.2). Removing a user blanks their leaf and full path,
exactly like an update proposal. The result shows the MLS standard's way of handling
removals is asymptotically optimal and cannot be improved by simple means — the blank-
accumulation overhead from membership changes is not an implementation artifact but a
provable lower bound.
