# Matching techniques

## Workflow that works

1. **Write a first version** from the original disassembly and a decompiler's output (Ghidra). Keep
   names and types from the analysis database so source and database can be read side by side.
2. **Fix the structure first**: the function's size and block order. A wrong size shifts everything
   after it, so compare instruction by instruction with alignment (see "Scoring") rather than bytes.
3. **Then registers and stack slots** (register-allocation.md). Write 3-10 variants of a suspicious spot
   and score them all at once; keep the best; repeat.
4. **Keep the TU's `.data` matching** at every step (literal order is part of the source).
5. For stubborn functions: a **permuter** search, then **compiler instrumentation** (c2-internals.md).
6. When a function can't be matched yet, **stand in the original bytes** so the executable still matches
   and the rest of the work stays verifiable by a hash.

## Levers: source changes that move specific things

Each entry says what it changes; all of them keep the program's behaviour. Examples in parentheses are
KGT functions where the lever was needed.

### Block structure

* **`if (0) goto L; L:;`** before a statement: an empty basic-block boundary that emits no code. It stops
  forward substitution (`op = X; off = op;` otherwise computes X straight into off's register), keeps
  instructions from being scheduled across it, and changes per-block reference counts and therefore
  allocation priorities. The dead `goto` must come before the label. Most useful as a search dimension:
  try one before each statement.
* **Duplicating a statement tail into both arms** of an if/else: VC6 merges the copies again, but the extra
  use changes register choices (vProcessEngineObjects, WinMain).
* **Removing a switch fallthrough**: give the case its own copy of the fallen-into statements and a
  `break`; the bodies are merged back, but allocation sees different edges (vjmpReadScript,
  vDrawCurrentEngineObject).
* **Splitting `case A: case B:`** into two identical cases adds constant uses (vjmpHandleBattleState).
* **Keeping two identical exits apart**: make what precedes them differ, e.g. jump to a second copy of
  shared code (`goto perfect2;`); VC6 then merges those copies instead (vjmpHandleBattleState).
* **Counted loops versus do-while**: `do { } while (--h)` and `iRow = h; while (iRow--) { }` differ in code;
  converting between them is safe when an earlier check guarantees at least one iteration
  (vBlitImageRect16).

### Which values are live together

* **Per-case locals** instead of one variable shared by several switch cases: a variable shared across
  cases ties all their register choices together (vBlitImageRect16: 92 -> 60 differences).
* **Statement order of independent statements**, especially the order of first assignments at a
  function's start (vBlitImageRect16's prologue).
* **Moving an assignment earlier or later** lengthens or shortens a web (`i = 1;` placement in
  vjmpHandleBattleInterface).
* **Computing a value from its source instead of from a copy** removes a use of the copy
  (`pSrc = pPalette + pImage->colorsUsed + 1` instead of `+ nColors` lowered nColors' priority).
* **Assigning call arguments to locals first** when the original evaluates them in an unusual order.

### Memory versus register

* **Dead address-taking**: `if (0) vMemzero(&v, 0);` (any call taking the address) removes `v` from register
  allocation completely, as when the original keeps a variable on the stack even in hot loops. Only real
  escapes count: `(void)&v` or `{ void *p = &v; }` do not.
* **Volatile-cast reads of a global**: `*(volatile int *)&g` for a global the original reloads at every
  use where ours caches it in a register. Avoid `volatile` on locals.
* **Reading a field through `&p->field`**: `pb = &p->b; ... x = *pb - 1;` keeps a load after an earlier
  store to another field (vAddToHealth); `{ void **pp = &p->a; free(*pp); }` forces a re-read.
* **Reading a parameter through a neighbour's address**, `*(T *)(&hModule + 1)` for the next parameter:
  the same stack slot under another symbol, so VC6 no longer shares one load between two uses
  (bGetWavFileInformation).
* **Using a struct field directly** instead of a local copy can give the original's byte load + spill.
* **Unnamed expressions instead of named copies** where the original modifies a register in place.

### Reference counts and expression shape

* **Dead stores / dead initializers** (`int x = 0;` overwritten before use; `p0 = 0;` after the last use)
  add a reference or an assignment: they change reload order at joins, tail merging, and the operand
  order of canonicalised sums (vHandleHitMovements, vDrawCurrentEngineObject).
* **Value-neutral casts**: `(short)a` where only low product bits survive, `(WORD)(x & m)`, `(int)d`:
  they change the conversion-node count and with it the evaluation order of terms (vDrawKgtImage16).
  Prove neutrality per term (which bits the mask keeps, what the extension can change).
* **Multiply versus shift** for the same value in two branches keeps VC6 from merging the computations.
* **Local types**: a `WORD` local instead of an `int` with a cast changed load/store order
  (vjmpHandleBattleState); `int a = (WORD)field` instead of `WORD a` changes where extensions happen.
* **Array-of-struct addressing**: `p = (T *)&arr[i - 1]; ... p[n + 1].field` reproduces "offset term +
  base - element" addressing that `arr[i - 1].sub[n].field` collapses into one index.
* **A plain loop instead of `memset`** gives a different `rep stosd` set-up order.
* **Count-down loops**: add a harmless second condition (`&&`) to keep an up-counting loop.

### Things that did not help (save your time)

Renaming; reordering declarations; `register`; adding parentheses; rewriting the same expression with
other operators or temporaries (normalised); most cast changes that don't change a value's width;
`for` versus `while` spelling of the same loop.

## Scoring

Byte comparison is misleading once a function's size differs. Score a candidate by **aligned instruction
differences**: disassemble both, resolve relocations to the original's addresses (symbols from a linker map
of a build that lays everything out like the original), normalise jump/call targets and switch-table
references to the function itself, then count differences after a sequence alignment. 0 = identical.
Report size separately; a variant with the right size is usually better than a lower score with the wrong
size.

## Searching

* **Variant files**: many OLD/NEW text replacements scored in one run. Generate them with scripts.
* **A permuter** (random source mutations, keep improvements). Two modes are useful:
  * free mutations - fast, but results change behaviour and are only usable as hints unless exact;
  * **safe mutations only** - dead block boundaries, dead initializers, dead address-taking, swaps of
    independent statements, duplicated tails, equivalent comparisons and loop forms. Every improvement
    found is directly usable. Most of the late progress in the KGT project came from this mode.
  Watch for mutation bugs: a "safe" mutation that rewrites `A && B == 0` into `!A && B` is not safe. Audit
  conditions and parentheses of anything a tool produced before trusting it.
* **Wide sweeps** are cheap (a full TU compile takes well under a second): insert one kind of change
  (boundary, dead store of each local) at every statement position and score all.
* **Hill climbs over spelling choices** (which operands get which value-neutral cast) found orders the
  compiler would not produce from the natural spelling.
* **Forced-decision experiments** in an instrumented compiler (c2-internals.md) tell you *which* allocator
  decision differs; then search for a source form that produces it. Blind searching without that
  information stalled repeatedly.

## Keeping the build byte-exact while functions don't match

* **Byte-exact stand-ins**: wrap an unmatched function as

  ```c
  #ifndef NONMATCHING
  __declspec(naked) int Func(...) { if (0) { /* the C body */ } __asm { _emit 0x55 ... } }
  #else
  int Func(...) { /* the C body */ }
  #endif
  ```

  The dead `if (0)` copy keeps the TU's string literals and symbol references (and so `.data` and the
  import order) unchanged. Write calls through the import table symbolically (`call dword ptr
  [GlobalFree]`) so the imports stay referenced. The default build is then identical and verifiable by a
  hash, and `/DNONMATCHING` builds the C.
* **Bank improvements** into the C version even when it doesn't match yet - but only behaviour-preserving
  ones, reviewed (token diff against the previous version) and play-tested.
* **Runtime bisecting**: when every function sits at its original address, a build can be patched
  function by function with the original's bytes to find which C function causes a runtime difference.
* **Tidying names and comments safely**: names and comments never change VC6's output, but moving or
  adding code can. Verify every tidy-up by (1) a token comparison of old and new source with comments
  stripped (only identifiers may differ), (2) the default build's hash, (3) the `NONMATCHING` build's hash
  and each unmatched function's score. Keep Shift-JIS bytes intact by editing through Latin-1.

## Working with agents

* Give each agent a self-contained brief: goal, current score, harness command, what was tried, the rules
  (behaviour-preserving only, don't commit, which checks must pass).
* Parallel agents must not build in the same directory: use one git worktree per agent (copy untracked
  tools such as the assembler binary into each).
* Ask for a notes file with what was tried; the negative results are what saves the next attempt time.
* Scope process clean-up by path; one agent's "kill my processes" killed another's search once.
