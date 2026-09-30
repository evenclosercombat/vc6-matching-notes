# How `cl` (VC6, `/Ox /Oa`) lays out data and code

Register and stack-slot allocation have their own file (register-allocation.md); this one covers
everything else that decides the bytes.

## Data

* A translation unit's `.data` is: its initialized globals in **definition order**, then the string
  literals used in global initializers, then the string literals of the functions **in source order of
  first appearance**. Every literal is 4-byte aligned.
* Without `/GF`, identical literals are **not pooled**: two `"%s.player"` in a TU give two copies.
* Literals in **dead code** (after a `return`, inside `if (0)`) are still emitted, in place. This is useful:
  a dead copy of a function body keeps a TU's literal order when the real body is replaced by something
  else (matching-techniques.md, "byte-exact stand-ins").
* All-zero literals (`""`) are not in `.data`: each becomes a 1-byte `.bss` contribution of its TU.
* Zero-initialized globals and statics go to `.bss`, not `.data`.
* A TU's `.bss` and its communal variables are **not** in declaration order: `cl` orders them by an internal
  hash of the name (for short names it behaves like `h = h * 4 + c` over the characters). Reproducing an
  original `.bss` layout from C declarations is therefore impractical. What works: define every
  uninitialized variable in an assembler object in the original order (ordinary `_BSS` for the plain part,
  communal definitions for the rest) and declare them `extern` in C (linker-and-postlink.md).
* `.rdata` holds `const` data such as SDK headers' `static const char c_szWAV[] = "WAV";`, even unused.

## Code layout

* **Functions** are emitted in source order and start on 16-byte boundaries; the padding between them
  comes out right by itself once every function has the right size.
* **Block layout follows the flow graph**, not where labels are written. Moving a `goto` target around the
  source changes nothing; changing the graph does. Example: `if (!a) goto err; if (!b) goto err; ok...;
  return 0;` gives "fall through into the error block, success last", while `if (a && b) { ok }` gives
  "success inline".
* `if (SUCCEEDED(x)) { ... } else warn();` puts the failure path last.
* **Tail merging**: identical instruction sequences before a common successor are merged, so a shared error
  tail (`open_error: sprintf(...); goto error; read_error: sprintf(...); goto error; error: warn(msg);
  return -1;`) shows up as one block jumping into the middle of another, and the stack cleanup of one call
  (`add esp, 0xc`) is not combined with the next call's.
* **Switches**: jump-table switches lay out the case bodies in source order; compare-tree switches in
  tree-walk order. Identical case bodies are merged.
* **Loops**: a `for (i = 0; i < n; i++)` whose counter is only a counter becomes a count-down loop; an
  `&&` in the condition (`i < n && i < m`) keeps the up-counting form. Loops over arrays are often
  strength-reduced to a pointer induction variable (a pointer walked by the element size) - the original
  index disappears.
* **`memset`/`memcpy`/`strcpy`** are inlined (`rep stosd`/`rep movsd`/`rep movsb` with fixed register
  set-up: `mov ecx` / `xor eax` / `lea edi` for memset). A plain loop that clears an array also becomes
  `rep stosd` but with a different set-up order (`lea edi` first). A `while (n--) *p++ = 0;` byte loop
  stays a byte loop.
* **Booleans**: `int b = 0; if (x) b = 1;` compiles to a compare and branch, where `b = (x != 0)` or
  `b = x & 1`-style expressions give `neg/sbb` or `shr/and` sequences.
* Small idioms: `return -1` when a register is known to hold -1 may become `or eax, reg`; `!ReadFile(...)`
  as a return value gives `neg eax / sbb eax, eax / inc eax`.

## Expression canonicalisation

The front end normalises expressions before the back end sees them. Useful to know which rewrites are
pointless and which are not:

* **Normalised away** (no effect on the output): names, redundant parentheses, operand order of
  commutative operators, most casts that don't change a value, `x * 2^n` versus `x << n` *inside one
  expression*, `for` versus `while` spelling of the same loop, a local copy of a value that is used once,
  inline helper macros.
* **Order of terms in sums of products** is decided by a weight: terms containing more conversion nodes
  (zero/sign extensions) are evaluated first; ties keep source order. So a value-neutral cast such as
  `(short)a` on an operand whose extra product bits are masked away moves a term earlier.
* **Sums of pointer loads** (`*p0 + *p1 + *p2 + *p3`): the operand order follows the reverse of the order in
  which the pointer variables are first assigned in the function. A dead store `p0 = 0; p1 = 0; ...`
  placed after the real uses changes it.
* **Narrow multipliers**: a `WORD -> int` extension feeding a multiply is dropped when only the low 16 bits
  of the product matter and the conversion has a single use after common-subexpression elimination. So
  `int a = (WORD)field;` gives raw register uses where a `WORD a` would be zero-extended once and shared.
* **Different spellings of the same value in two branches** (`a * 0x10000` in one arm, `a << 16` in the
  other) are *not* merged across the branches, while identical spellings are: a way to keep the
  compiler from hoisting a common computation.

## Frames and calls

* Functions use `esp`-relative frames (no frame pointer, `/Oy`); `sub esp, N` then pushes of the callee-saved
  registers it uses, in the order ebx, ebp, esi, edi.
* Call arguments are pushed right to left; the caller pops with `add esp, N`, and consecutive cleanups are
  combined unless a merged tail sits between them.
* Parameters that are dead can have their stack slots reused for locals (frames below 0x70 bytes; see
  register-allocation.md).
* `__declspec(naked)` functions get no prologue/epilogue, so `__asm { _emit ... }` inside one reproduces
  arbitrary bytes exactly.
