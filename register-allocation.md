# Register and stack-slot allocation: the practical rules

Most differences left after a function has the right shape are register choices and stack-slot
positions. This file states the rules as they are useful when editing source; c2-internals.md has the
compiler-side details (function addresses, exact formulas, how they were established).

The first half was established with small test programs, the second by reverse-engineering the back end
and confirmed with instrumented copies of it.

## Rules from test programs

* **The unit is the live range ("web"), not the variable.** Copies are coalesced before priorities are
  computed, so introducing a local copy of a value changes nothing by itself, and one variable reused for
  unrelated purposes gives the same code as two variables.
* **Colouring order is priority order.** Values that live across a call get callee-saved registers in the
  order esi, edi, ebx, ebp; values that cross no call take eax, ecx, edx first.
* **Priority** is roughly defs + uses, each weighted 2^(loop depth). A longer range, counted in basic blocks
  (not instructions), lowers it. On equal priority the web **defined first** wins; declaration order and
  first-use order do not matter.
* **Constants** get their own register candidate when they are used often enough (across calls: at least
  about 6 uses) and count about half: constant 1 with U uses beats a variable with k uses only when
  U >= 2k + 7. Splitting a `case A: case B:` into two identical cases adds a use (the bodies are merged
  again afterwards) and can put a constant into a register.
* **Copies are preferences.** For `if (c) i = X; else i = 1;`: if X was coloured before i and is dead after
  the copy, i takes X's register; if X is still live after the join, i gets a fresh register and both
  paths copy; if the constant's web was coloured before both, i shares the constant's register.
* **Named variables keep their register**: a named variable's register is never overwritten in place. An
  instruction like `and edi, eax` applied to a value in the original means the value was an *unnamed*
  common subexpression - write the expression (`pInputs[iPos] & iButtons`) instead of a named copy.
* **Taking a variable's address** (anywhere, even in dead code) keeps it in memory for the whole function.

## Rules from the back end

### Register candidates

* **Priority** of a candidate = for each block that references it: + block weight x number of candidates
  referenced in that block x ~2 per reference; for each block it is live across without a reference:
  - block weight x that count. Block weight = 2^(loop depth); loops made with `goto` count.
* The highest priority is coloured first; ties go to the larger internal id, which in practice is the
  variable defined first.
* Zero constants, repeated import addresses (`call [__imp__X]` loaded into a register) and
  strength-reduction temporaries (the base or offset of a walked array) are candidates too.
* Every candidate also has a **benefit** (summed per reference). Candidates with benefit below 1 - or with
  fewer than 3 references - go to the spill path and usually live in memory. A value that must be reloaded
  after calls gets negative benefit contributions, so webs crossing many calls tend to be spilled or split.
* **Allocation runs in rounds.** After each assignment the register is removed from every overlapping
  candidate still waiting. A candidate with no register left is split or spilled, and all priorities are
  recomputed; the per-block count only includes candidates not yet assigned, so long-lived variables gain
  priority as the function fills up.
* **Choosing among free registers**: each register gets a cost from the *uncoloured* interfering
  neighbours that want it (a neighbour that can only use or prefers eax makes eax expensive, scaled by
  that neighbour's benefit), plus copy preferences of the candidate itself. On equal cost the order is eax, ecx, edx, esi, edi, ebx, ebp. This is why a value can
  take ebx in one function and ebp in an almost identical one: it depends on which neighbours are still
  waiting.
* **Splitting**: a split piece grows block by block along the flow graph while some allowed register is
  still free of earlier colourings; reloads go where the set runs empty, spill/reload copies on the
  piece's boundary edges. Per-case single-reference pieces of one variable come from this.

### Stack slots

* **Slot weight** = number of memory operands naming the variable in the code after register allocation,
  counted before identical tails are merged and before store+reload pairs become register moves.
* **Slot order**: by size (smaller first), then weight (higher first); on equal weight the variable that
  reached its count first in code order comes first. Parameters get their slots first; each local joins
  the most recent slot it can share (size at most twice the slot's, lifetimes not overlapping), else opens
  a new one; a shared slot sits at its first member's position.
* **Frames over 0x80 bytes**: slots are then quicksorted by weight * 1000 / size (highest first), an
  unstable sort with a middle pivot, so equal weights come out permuted in a fixed but non-obvious way.
* **Frames of 0x70 bytes or more** don't reuse dead parameter slots for locals.
* Slot order follows live ranges and use counts after allocation, not declarations, types or text order:
  making a variable live longer, or giving it one more memory operand, moves its slot.

## What does and does not influence allocation

Does not: names; declaration order (almost never); casts, macros, loop spelling, operator order, inline
helpers, extra local copies; `register` (no effect observed).

Surprising exception: **unused initialized locals** (`int pad = 0;` never read) can matter - removing a
few of them changed a large function's allocation completely (vBlitImageRect16: from 60 differences to
about 290). They shift internal numbering, which decides priority ties. Keep such locals once a search
has found them useful, and label them as scaffolding.

Does:

* control-flow edges: block boundaries, a switch fallthrough versus a copied statement and `break`, a
  statement copied into both arms of an if/else, duplicated tails;
* which values are live at the same time: where a variable is first assigned, statement order of
  independent statements, per-case locals versus one variable shared by several switch cases;
* whether a variable is in memory: dead address-taking, reading a field through a pointer made with
  `&p->field`, reading a parameter through a neighbour's address;
* reference counts: a dead store, an extra (even redundant) use, a value-neutral cast that changes the
  number of conversion nodes.

See matching-techniques.md for each of these as a recipe.
