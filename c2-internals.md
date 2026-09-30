# Inside `c2.dll`: the VC6 back end, reverse-engineered for matching

This is a reference for people and agents who need to know *why* Visual C++ 6.0 chose a register, a
stack slot or an operand order, and who are prepared to instrument the compiler to find out. It
collects what was learned by decompiling `c2.dll` in Ghidra and running patched copies of it during
the KGT byte-matching project. The practical rules that follow from it are summarised in
[register-allocation.md](register-allocation.md); the source-level levers are in
[matching-techniques.md](matching-techniques.md). This file is the "how it works inside" layer
underneath both.

KGT function names (`vBlitImageRect16`, `bReadKgtCore`, ...) appear only as examples of where
something was observed.

**Status markers.** Each claim is tagged:

* **[E] established**: read in the decompiled code *and* confirmed by traces or forced experiments;
* **[O] observed**: consistently seen in traces or test compiles, mechanism not fully decompiled;
* **[I] inferred**: a reading of decompiled code or a hypothesis that fits the data but was not tested.

All addresses are virtual addresses in the image loaded at its preferred base (see 1.1); Ghidra names
such as `FUN_10720610` are those addresses.

---

## 1. Setup and instrumentation

### 1.1 The binary

| property | value |
|---|---|
| file | `C:\Program Files (x86)\Microsoft Visual Studio\VC98\Bin\c2.dll` (VC6 RTM) |
| file version | 12.00.8168.0 (goes with `cl` 12.00.8168) |
| size | 737,329 bytes |
| SHA-256 | `ab12de95a848429bfc2aa6ad4131e8587cfe0c953e98220ca4c77eeed8d4683c` |
| PE timestamp | 0x35880E04 (June 1998) |
| image base | **0x10700000** |
| `.text` | VA 0x10701000, virtual size 0x97042, raw size 0x98000 (so ~0xFBE bytes of zero slack at 0x10798042..0x10799000) |
| other sections | `.bssbe`, `.rdata` 0x107A0000, `.data`, `.databe` 0x107AC000, `.rsrc`, `.reloc` |
| imports | `mspdb60.dll`, `USER32`, `MSVCRT` (40 functions, including `vfprintf` and `_iob`), `KERNEL32` |

Assertion strings name the internal source files: the register allocator lives in `color.c` /
`regasg.c`, the frame layout in `stack.c`.

Everything below was observed with the flags `/nologo /c /Ox /Oa /W3` on 32-bit x86 C code. A global
flag that the allocator tests (`DAT_107ac0b0`, "optimising") is set in this configuration; other flag
sets (in particular `/Od`, and possibly `/Oy-` or `/G*` variants) take other paths that were not
studied.

If your `c2.dll` differs in size or hash (a service pack), every address in this file is suspect;
the structure of the algorithms probably is not.

### 1.2 Loading another back end: `cl /B2<path>`

`cl.exe` is only a driver: it runs the front end (`c1.dll`) and the back end (`c2.dll`). The option
`/B2<path>` (no space) makes it load the back end from `<path>` instead of the installed one [E; used
thousands of times]:

    cl /nologo /c /Ox /Oa /W3 /B2C:\work\c2_trace.dll foo.c

So the method is:

1. **Never modify the installed `c2.dll`.** Every experiment writes a *copy* with a new name and
   passes it with `/B2`. A normal compile without `/B2` is then always the reference.
2. Make patched copies with a script that reads the installed file, asserts the bytes it is about to
   change, and writes the copy (examples: `sa15\mkpatch.py`, `sa15\mkpatch2.py`,
   `sa15\c2patch\mkhook.py`).
3. The copy must load at its preferred base 0x10700000. The hook code uses absolute addresses and is
   not covered by `.reloc`; in practice `cl` always mapped it at its base.

No Microsoft binary is included with these notes; the scripts named below regenerate the copies from
an installed VC6.

### 1.3 Static analysis

`c2.dll` was loaded into a separate scratch Ghidra project (not the game's project) and driven from
Python through a small persistent pyghidra server (`sa15\c2server.py`, `bl21\c2server.py`: opens or
creates the project, runs auto-analysis once, then executes Python snippets sent over a local TCP
socket, with helpers `decomp(addr)`, `dis(addr, n)`, `xrefs_to(addr)`, `strs(regex)`; client
`c2.py`). Decompilations were saved as `d_<address>.c` next to the notes. For quick looks without
Ghidra: `dk28\c2dis.py VA N` (capstone disassembly of the installed file), `dk28\xref.py VA`
(rel32 call/jmp sites that target VA), `hb29\c2scan.py REGEX lo hi` (linear disassembly grep, e.g.
"every write to `[reg+0x3c]`" to find who changes the benefit field).

### 1.4 Byte patches (no new code)

Two small patches of the stack-frame code were enough to read its internal state from the ordinary
`/FAs` listing [E]:

| copy | patch | effect |
|---|---|---|
| `c2_nosort.dll` (`mkpatch.py`) | 5 NOPs over the `call` at 0x10726D36 (the quicksort call in the frame packer) | frame records appear in their pre-sort list order |
| `c2_weights.dll` (`mkpatch2.py`) | as above, plus `jg`->`jmp` at 0x1072706C (no slot sharing) and at 0x107270FF record size := 5 x weight (`lea edx,[esi+esi*4]`) | every slot's size encodes its walk weight; `wts.py` prints the weights from the frame offsets |

### 1.5 Hook DLLs (trace output)

`sa15\c2patch\mkhook.py OUT.dll HOOKS.asm` builds a traced copy:

* the hook code is a NASM `-f bin` file with `org 0x10798100`, assembled and written into the zero
  slack at the end of `.text`; the section's virtual size is raised to its raw size so the slack is
  mapped;
* the file begins with a table of 5-byte `jmp strict near hook_x` slots; directives of the form
  `;HOOK <va> <len> <slot>` make the script overwrite `len` bytes at `va` with `jmp slot` plus NOP
  padding. `len` must cover whole instructions;
* each hook does `pushad / pushfd`, prints, `popfd / popad`, then **re-executes the instructions it
  overwrote** and jumps back to `va+len`. Getting this replay exactly right is the only delicate part;
* printing calls MSVCRT's `vfprintf` through `c2.dll`'s own import table (IAT slot 0x107A00C4) with
  `&_iob[2]` (stderr; the `_iob` pointer is at 0x107A0074, +0x40). `c2.dll` runs inside the `cl.exe`
  process, so the text appears on `cl`'s stderr and a runner just captures `cl`'s output;
* a candidate's name is `[[[cand]]+0x18]` (the symbol name, `_x` style); unnamed temporaries and
  constants print as `?`.

Runners (`sa15\ratrace.py`, `bl20\rt.py`, `bi25\rt2.py`, `rk26\rt13.py`, `dk28\rt3.py`) compile a file
with `/B2<dll>`, split the output into per-function blocks at the `FN` lines and print the block of one
function. Compiling a *mini TU* (the whole translation unit with every other function body emptied,
`sm23\mini2.py`) gives the identical trace in ~0.3 s.

Hook points used, and what the hook prints:

| hook address | inside | line(s) | contents |
|---|---|---|---|
| 0x10720610 | allocation driver entry | `FN name` | function being allocated (starts a block) |
| 0x10715922 | queue insert | `INS name prio id idx refs [ben]` | every (re)insertion of a candidate into the priority queue |
| 0x1071700B | spill path | `ASG name prio id idx [ben]` | candidate sent to the spill path |
| 0x107159AF | colouring routine | `SPL name prio id idx` | candidate about to be coloured |
| 0x1071689A | register choice | `REG ... pref[0..8]` (`dr19\c2\trace12.asm`) | the cost array at the choice |
| 0x107169C9 | after the choice | `REG name idx id r=N` (+ `NB` neighbour lines, + `COST`/`PREF`) | chosen register; uncoloured interfering neighbours with their allowed set; the full cost array, own benefit and preferences (`rk26\mk13.py`) |
| 0x1075BD93 | no-register path | `NOR ...` | candidate whose allowed set is empty when dequeued |
| 0x10714465 | priority computation | `BLK blk [..] N=.. w=.. \| R:name#id*units L:name#id` (`trace7.asm`) | per-block contributions: referenced (R) and live-through (L) candidates |
| 0x10714AD3, 0x1071486A, 0x10714586, 0x10714715 | priority computation | `H1 B1..B4 id idx units w op tup blk ben` (`hb29\t15c.asm`) | the four benefit updates: use, def, store subtraction, reload subtraction |
| 0x10714C06, 0x10714C25, 0x10714C53 | priority computation | `H2 P+`, `H3 P-` (`hb29\t15d.asm`) | per-block priority additions/subtractions |
| 0x10725200 | spill/split routine | `SPC n=.. dat=..` (`bi25\t13.asm`) | size of the emptied set and the global `DAT_1079e88c` |
| 0x1072561A | per-candidate split | `SPM name prio id idx ben regs` | each candidate carved into pieces |
| 0x107683E3, 0x10768405, 0x1076841D, 0x10768492, 0x107684E4, 0x1076874A, 0x10768763, 0x10768792, 0x10768E10 | coalescing / rematerialisation | `COE CO CR P92 RM RFA RFB E10` (`dk28\t20..t23.asm`) | entry, intermediate results and the final compare of those routines |
| 0x10733AC7, 0x10735188 | frame layout | `STK name w caller` (`sa15\c2patch\trace8.asm`, `dr19\mkstk.py`) | every symbol reference counted by the stack walk, in walk order |

Useful candidate fields to print are listed in section 2.3.

### 1.6 Forcing decisions

The most productive tool was not the trace but **forcing**: a hook that changes one number and lets the
compiler finish, so you can see what the code would look like if the original had taken that decision.

`bl20\mkforce.py OUT.dll FUNC rule...` (later versions `bi25\mkforce2.py`, `hb29\mkforce3.py`,
`mkforce4.py`, `rk26\mkforce13.py`, `dr19\force.py`) generates a trace DLL whose insert hook starts
with rule code:

* the `FN` hook compares the function name with `_FUNC` and sets an `active` byte, so the rules fire
  only inside that function. The byte lives in the cave inside `.text`, so the script also sets
  `IMAGE_SCN_MEM_WRITE` in the `.text` section characteristics;
* rules, applied at every queue insertion:

| rule | effect |
|---|---|
| `id:+d`, `id:-d` | add d to the priority (`cand+0x0C`) of candidate `id` every time it is inserted |
| `id:old:new` | set priority to `new` when it is exactly `old` (targets one piece in one round) |
| `id:*:new` | set it at every insertion |
| `q<idx>:<old or *>:<d>` | same for a constant piece (id 0), selected by its index `cand+0x1C` |
| `B<id>:<prio or *>:<ben>` | set the **benefit** `cand+0x3C` (the spill decision uses it, not the priority) |
| `b<idx>:<refs or *>:<ben>` | set the benefit of a constant piece |

Because all priorities are recomputed after every rebuild (3.8), a `+d` rule applies to every round,
while `old:new` hits a single piece of a single round. A forced benefit can be overwritten by the next
recomputation (the `b` rule had no effect for that reason in one case).

Search drivers built on this: parallel forced compiles (`frs.py`, `frh.py`), single-id scans over all
trace ids with +/-3..60 (`bl20\scanp.py`, `dr19\fscan.py`, `sm23\scanf.py`, `bi25\scanq.py` for
constant pieces), coordinate descent and simulated annealing over deltas (`bl20\cdforce.py`,
`bl20\saforce.py`). Forced DLLs can be cached by a hash of their rules (`dr19\c2\f_<hash>.dll`).

Practical notes: a patched `c2` can hang on some inputs (use a timeout per compile); do not name a
helper script `dis.py` in a directory from which Python tools are run (it shadows the standard module
and every compile "fails").

---

## 2. Map of the relevant functions and data

### 2.1 Register allocation (`color.c` / `regasg.c`)

| address | role | status |
|---|---|---|
| `FUN_10720610` | **allocation driver** for one function: builds candidates, computes priorities, runs the queue loop and the rebuild rounds, for two register classes in turn (class 1 then class 0; class 0 = the 32-bit general registers) | E |
| `FUN_1072159B` | builds the candidate set / interference for a class | I |
| `FUN_1071431D` | **priority and benefit computation** over all blocks (also records copy preferences, first/last block, reference counts) | E |
| `FUN_10714EEB`, `FUN_107152C2`, `FUN_10714C76` | per-reference "units" helpers used by `FUN_1071431D` (use/def weights; `FUN_107152C2` and `FUN_10714C76` also price spill stores and reloads) | E (called), I (exact values) |
| `FUN_10714F83` | add a **preference** (affinity) of a candidate for a register or for another candidate's register | E |
| `FUN_10715308` | fills the priority queue | I |
| `FUN_10715922` | **queue insert**: sorted by priority descending, ties by id descending | E |
| `FUN_1071700B` | **spill path** ("ASG" in traces), taken when benefit < 1 | E (entry), I (details) |
| `FUN_107683E3` | copy-coalescing helper (lowers a copy's priority below its partners so they are coloured first); gated by candidate flag 4 | E (code), never runs here (3.9) |
| `FUN_10768492` | rematerialisation pass inside the colouring routine; same gate | E, never runs here |
| `FUN_1076835B`, `FUN_10768571` | remat helpers: collect the operand candidates of a definition; count uses against a cost | E (code) |
| `FUN_10768E10` | **rematerialisation** test for a neighbour that lost its last register; same gate | E, never runs here |
| `FUN_107159AF` | **colouring routine** for one candidate ("SPL" in traces); returns a set of candidates to rebuild | E (role) |
| `FUN_1078E7FE` | called from `FUN_107159AF` in a loop when a count exceeds its limit parameter; each call returns a candidate; looks like choosing values to spill where register demand in a block is too high | I |
| `FUN_10716715` | **register choice**: per-register cost from uncoloured neighbours' preferences and own preferences; lowest cost wins, ties by class order | E |
| `FUN_107169C9` | **register removal / propagation** after a choice: removes the register from every uncoloured interfering neighbour; neighbours left with no register are split or spilled | E |
| `FUN_1075BD93` | candidate dequeued with an empty allowed set ("NOR") | E (entry) |
| `FUN_107251E5` | **spill/split** of a set of candidates that lost all registers | E |
| 0x10725200 | inside `FUN_107251E5`: the `n < 3` test that picks per-candidate splitting | E |
| `FUN_1072561A` | per-candidate split: walks the candidate's blocks and forms pieces | E |
| `FUN_1072588B` | **piece growth** within a block: tracks which allowed registers stay free | E |
| `FUN_10724C87` | inserts a reload/spill tuple at the point where the free set runs empty | E |
| `FUN_10723B3E` | rewrites the IL after a split (part of the rebuild) | E (role) |
| `FUN_10724C3F`, `FUN_10724075` | re-queue after a rebuild, queue cleanup | I |
| `FUN_10722DC2`, `FUN_1078E727` | remat rewrite and restart (unreachable in this configuration) | I |
| `FUN_1074C92B`, `FUN_10725131` | called from `FUN_107169C9` for special candidates; never entered in the functions traced | O |
| `FUN_1074FFBB`, `FUN_10724DC7`, `FUN_10715583`, `FUN_10716D02`, `FUN_1071715C`, `FUN_10717220` | helpers of the spill path (split for rebuild, leave in memory, requeue) | I |
| `FUN_10733E7E` | called by the driver after both classes | not studied |
| `FUN_10721174` | driver path when there is nothing to allocate | I |

### 2.2 Stack frame (`stack.c`)

| address | role | status |
|---|---|---|
| `FUN_10733AC7` | frame layout entry | E |
| `FUN_10734AF8` | walk over the code counting memory references per symbol | E |
| `FUN_10735188` | adds one reference of a symbol to the list (hook point for the walk trace; callers distinguish definitions and uses) | E |
| `FUN_10726A52` | packs symbols into records (slots); contains the quicksort call at 0x10726D36 and the sharing test at 0x1072706C | E |
| `FUN_10750F58` | the quicksort | E |

### 2.3 Data and the candidate record

| address | meaning | status |
|---|---|---|
| `DAT_1079D854`, `DAT_1079D858` | candidate sets for class 0 and class 1 | E |
| `DAT_1079D864` | head of the priority queue (doubly linked through `cand+0x14`/`+0x18`) | E |
| `DAT_1079D868` | cost array (9 dwords, indexed by register number) filled by `FUN_10716715` | E |
| `DAT_1079D860` | set of candidates whose preferences are updated after a choice | I |
| 0x107AC730 | register descriptor table, 0x54 bytes per register; `cand+0x10` points into it; register number at `desc+0x1C` | E |
| `PTR_DAT_107A0A14[class]` | zero-terminated register order list per class (class 0 list at 0x107A09F0: eax ecx edx esi edi ebx ebp) | E |
| `DAT_10799034[class]` | set of registers of the class | I |
| `DAT_107AC190` | caller-saved registers (removed at call tuples) | E |
| `DAT_107AC194` | when 0, ebp (6) is removed from the registers offered to the splitter | I |
| `DAT_107AC0B0` | optimisation on (enables loop-depth weights and some spill rules) | I |
| `DAT_1079E88C` | a counter reset per function; `FUN_107251E5` uses a global region splitter when >= 100 | E (test), meaning unknown |

Register numbers: 1 eax, 2 ecx, 3 edx, 4 ebx, 5 esp, 6 ebp, 7 esi, 8 edi.

Candidate record (pointer usually called `cand`). The fields printed or forced by the hooks (+0x0C,
+0x10, +0x1C, +0x20, +0x24, +0x3C, +0x40) are established; the meanings of the flag bits are read
from the decompilation [I]:

| offset | field |
|---|---|
| +0x00 | pointer to the symbol / value node (`[[cand]]+0x18` = name; byte `[[cand]]+4` = kind, 0x0D for constants and hard-register pseudo values) |
| +0x05 | flag byte: bit 0x04 = "no coalescing / remat" gate (3.9); 0x40 = already deferred once by the spill path; 0x80 = special splitting; 0x02 = split |
| +0x06 | flag byte: 0x01 special spill, 0x08/0x10 per-block bookkeeping in `FUN_1071431D` |
| +0x07 | count used by the spill path (0 means "leave in memory") |
| +0x0C | **priority** |
| +0x10 | assigned register descriptor (0 while uncoloured) |
| +0x14, +0x18 | queue links; +0x18 also accumulates units per block during the priority computation |
| +0x1C | index (`idx` in traces) |
| +0x20 | pointer to the **allowed register set** (bitset; bit r = register r) |
| +0x24 | reference count (`refs`) |
| +0x28, +0x30 | first and last block of the range |
| +0x34 | preference list: nodes `{next, target, weight}` |
| +0x38 | last defining tuple (used by the coalescing flags) |
| +0x3C | **benefit** |
| +0x40 | **id** (0 for constant pieces) |

---

## 3. The register allocator

### 3.1 Overview

VC6 uses a priority-based graph colouring allocator in the style of Chow and Hennessy: candidates
(webs, later pieces of webs) are coloured one by one in priority order; a candidate that runs out of
registers is split into pieces that get fresh priorities. In outline [E, from `FUN_10720610`]:

    for class in (1, 0):
        build candidates and interference                       FUN_1072159B
        compute priority and benefit of every candidate          FUN_1071431D
        fill the queue                                           FUN_10715308
        while queue not empty:
            if a rebuild set is pending:                         (a "round")
                rewrite IL for the split pieces                  FUN_10723B3E
                recompute ALL priorities and benefits            FUN_1071431D
                rebuild / re-queue                               FUN_10715308, FUN_10724C3F
            cand = pop highest priority
            if benefit < 1 and (benefit != 0 or cand spans more than one block
                                or cand is a kind-0x0D value or refs < 3 or not optimising):
                rebuild_set = spill_path(cand)                   FUN_1071700B  ("ASG")
            elif not flag4(cand) and coalesce(cand):             FUN_107683E3  (never, see 3.9)
                re-insert cand
            elif allowed(cand) is empty:
                rebuild_set = no_register(cand)                  FUN_1075BD93  ("NOR")
            else:
                colour(cand)                                     FUN_107159AF  ("SPL")
                pick register                                    FUN_10716715  ("REG")
                rebuild_set = remove register from neighbours    FUN_107169C9

Note that the choice between "colour" and "spill" looks at the **benefit**, while the order of the
queue is the **priority**. Many surprises come from mixing up the two.

### 3.2 Candidates

* The unit is the **web** (def-use live range), not the variable; after a split, the **piece**. [E]
* Besides named locals and parameters, candidates include unnamed temps: CSE values (e.g. a
  `pInfo->field` load used several times), repeated import addresses (`__imp__X`), **constants**
  (including zero, materialised as `xor reg,reg`), and pseudo values for hard registers such as a call
  result (kind 0x0D, id 0). [E]
* A variable whose address is taken anywhere (even in dead code) is **not a candidate** at all; it
  lives in memory for the whole function. [E] (`if (0) vMemzero(&v, 0);`). Taking the address
  without letting it escape (`(void)&v;`, `{ void **pp = &v; }`, compare or dereference only) does
  not count: it is optimised away before allocation. It must reach a call argument or a global
  store. [O]
* A global scalar read several times becomes a CSE candidate; `*(volatile int *)&g` per read prevents
  that. [O]
* A candidate undefined on some path into a join gets a zero-unit "pseudo definition" reference in the
  predecessor block of the join; it counts in that block's N (below) and produces a reload if the
  candidate is in a register afterwards. [O]
* Code-free statements (`x = x;`, `(void)x;`, `if (x) {}`, `x * 1`, `x + 0`, comma forms, dead stores
  of a value that is never read on any path, `if (x == x)`) are removed before allocation and add no
  reference. [O]
* Ids: fresh pieces and later-created webs get new, larger ids. For plain variables in small tests the
  **variable defined first ended up with the larger id** (which is why "ties go to the variable
  defined first"), but ids are not source order in general: a dead address-taking of another variable,
  or a split, renumbers. [O]

### 3.3 Priority

Computed by `FUN_1071431D` for every candidate of the class, walking the blocks in block-list order
[E]:

    w_b  = 1 << loopdepth(b)             (byte at block+0x6E; CFG loops, goto loops count too;
                                          w_b = 1 when not optimising)
    N_b  = |candidates referenced in b that die in b|
         + |candidates live at the end of b and referenced in b|
         + |other register temps referenced in b|
           (only candidates not yet coloured are counted)

    prio(c) = sum over blocks b that reference c:  w_b * N_b * units_b(c)
            - sum over blocks b where c is live at the end but not referenced:  w_b * N_b

`units_b(c)` is the sum of per-reference units in the block (accumulated in `cand+0x18`), each
coming from `FUN_10714EEB`, `FUN_107152C2` or `FUN_10714C76` depending on the reference and tuple
kind. Typical values are 2 per use or definition; constants and some copies contribute 0. [E for the
structure, O for the unit values]

Consequences that matter for matching:

* A block contributes in proportion to *how many other candidates it touches* (N_b). Blocks in hot
  loops with many values (pixel loops) dominate. Example: an iOtherX piece = right arm 64 x 8 + left
  arm 64 x 6 + compare block 144 x 2 = 1184 (the `H2` trace shows `nw = N_b * w_b` and units per
  block). [E]
* Every block a candidate is merely live across costs it `w_b * N_b`. A longer range therefore
  *lowers* priority, and an extra branch arm or edge block where the variable is live but unused is a
  pure penalty. Empty `if (0)` blocks and `?:` compiled to `setcc` are not blocks and cost nothing;
  real branches (with a store, call, return) and loops do. [E/O]
* Because N_b counts only uncoloured candidates, **priorities change from round to round**: long
  webs gain priority as their neighbours get coloured. [E]
* A new edge block can be created by moving an assignment into a branch arm: in
  `iLoadExternalImage`, writing `if (p->biClrUsed != 0) { n = p->biClrUsed; goto have; }` instead of
  `n = p->biClrUsed; if (n != 0) goto have;` put the copy into its own edge block (N=2) where pHeader
  was live but unreferenced: pHeader -2, which was exactly the tie needed. Same code. [E]

The empirical rules found earlier with test programs ("defs + uses weighted 2^depth", "each spanned if
block costs about 1/10 to 1/8 of a reference", "if/else arms weigh 1/4", "switch arms 1/2 to 1") are
approximations of this formula.

### 3.4 Benefit

Also computed in `FUN_1071431D` and stored at `cand+0x3C` [E]:

    ben(c) = sum over references r of c:   units(r) * w_b(r)
           - sum over spill STORE tuples (op 0x164) already in c's range:   FUN_107152C2(..) * w_b
           - sum over RELOAD tuples (op 0x163) already in c's range:        FUN_10714C76(..) * w_b

Before any splitting there are no spill tuples, so benefit is positive for any web with real
references. After a split, pieces inherit the reload/store tuples placed at their boundaries, and a
piece whose references are outweighed by those tuples gets benefit <= 0 and goes to the spill path.

Worked example (`vHandleHitboxEffects`, loop counter `j`, round-2 piece, `hb29` H1 hooks): def `j=0`
+4 (w 2), its store -4, head use +8 (w 4), reload at the inner-loop exit -8, `j++` use +8, def 0,
store -8, compare `j < 20` +8: benefit 8, so the piece is coloured. A sibling pointer web with the same
shape but no compare of its own sums to 0 and is spilled. The original evidently kept `j` in memory,
i.e. its piece had benefit <= 0. [E for the arithmetic]

### 3.5 Queue order and ties

* Queue: priority descending; **ties go to the larger id**. [E]
* Register choice ties: first register in the class order list (3.7). [E]
* After allocation, reloads emitted at the same point come out in ascending candidate index
  (`cand+0x1C`). [O]

### 3.6 The spill path (benefit < 1)

The driver sends a candidate to `FUN_1071700B` when `ben < 1` and at least one of: `ben != 0`, the
range spans more than one block, it is a kind-0x0D value, `refs < 3`, or the optimiser flag is off
[E]. Consequences:

* A candidate with fewer than 3 references and no positive benefit is usually left in memory. [E]
* The *priority* of such a candidate is irrelevant; forcing it does nothing. Only forcing the benefit
  (`B<id>` rule) changes the outcome. [E]

Inside the spill path [I, from the decompilation]: the first time a candidate arrives while others are
queued it is flagged 0x40 and deferred; a single-block candidate (or one with count byte +7 = 0) is
simply left in memory; otherwise it is split (`FUN_1074FFBB`, or `FUN_10724DC7` for the special kind)
and returned together with other deferred candidates of the same kind as a rebuild set, which starts a
new round. Its pieces come back with fresh priorities and benefits; a small piece around a dense use
region can then be coloured. This is how a value can be "memory at the top, register in the loop".

### 3.7 Register choice and cost

`FUN_10716715(cand, class, neighbours)` [E]:

    cost[r] = 0 for all r
    for each interfering neighbour n that is NOT yet coloured and has ben(n) > 0:
        for each preference (r, weight) of n with r still in allowed(n):
            cost[r] += weight
        if allowed(n) contains exactly one register r:
            cost[r] += 100 * ben(n)
    for each own preference (r, weight) of cand:
        cost[r] -= weight
    choose the allowed register with the lowest cost, scanning the class order list
        eax ecx edx esi edi ebx ebp
    (strict "<", so equal costs go to the earlier register)

Consequences:

* The choice is **not** only about the candidate itself: an uncoloured neighbour that can only use one
  register makes that register expensive by 100 x its benefit. Observed values: `pref[ebp] = 1700`
  (a neighbour with ebp only and benefit 17), `900` (benefit 9) in `vjmpHandleBattleInterface`;
  values like `399` combine such a term with preference weights (the exact decomposition of that one
  was not checked). [E for the rule, O for the specific numbers]
* A neighbour's **copy/hard-register preferences** also push the candidate away: in `bReadKgtCore`,
  colouring `n` first did not give it eax, because the uncoloured `pTable` web (preference eax from
  the call result, benefit 2) added cost to eax. Only when that web had gone through the spill path
  (benefit < 1, so it no longer counts) did `n` get eax. [E]
* With no preferences in play, webs that cross no call get eax, ecx, edx first; webs crossing a call
  can only use callee-saved registers and take esi, edi, ebx, ebp in that order. [E/O]
* After the choice, the register is recorded in the per-block used sets, and candidates in the
  pending-preference set get a preference for it via `FUN_10714F83` (so copy partners coloured later
  tend to follow). [E for the calls, I for the effect]

A `REG` trace line with the cost array (`rk26\mk13.py`, `dr19` `c2_r1`/`c2_r2`) answers most "why
this register" questions directly.

### 3.8 Register removal, splitting and rounds

`FUN_107169C9(func, class, cand, neighbours, returned_set)` after the choice [E]:

1. For each uncoloured interfering neighbour, remove the chosen register from its allowed set.
2. A neighbour whose set becomes **empty**: if flag 4 is clear, try rematerialisation
   (`FUN_10768E10`; never happens here, 3.9); otherwise collect it. Neighbours with flag 0x80 go to a
   separate list (kind 0x0D ones to `FUN_10725131`).
3. The collected set goes to `FUN_107251E5` (spill/split) with the class's registers (minus ebp when
   `DAT_107AC194` is 0).
4. All of them, plus the set returned by the colouring routine, are returned to the driver as the
   rebuild set: IL rewrite, **recompute every priority and benefit**, requeue. That is a *round*.

`FUN_107251E5(func, set, regs)` [E]: if fewer than 3 candidates were emptied at once, or
`DAT_1079E88C < 100`, each candidate is split individually by `FUN_1072561A`; otherwise a region
algorithm over all blocks handles the whole set (block+0x48 = candidates live, +0x4C = registers used).
Only the per-candidate path was ever observed (`SPC` lines: e.g. n=10, dat=79).

**Piece growth** (`FUN_1072561A` -> `FUN_1072588B`) [E]:

* The candidate's blocks from `cand+0x28` to `cand+0x30` are walked. At a block where the candidate is
  live and not yet in a region, a new region number is started and grown through successor edges
  (block+0x0C successor list; target+0x40 = live-in set) as long as `FUN_1072588B` says some allowed
  register survives.
* `FUN_1072588B` walks the block's tuples with a set of free registers, removing every register held by
  an operand that is an already-coloured candidate (kind 2: its register) or a hard register (kind 1);
  a call tuple (flag 0x20000) removes all caller-saved registers (`DAT_107AC190`). When the set runs
  empty at a tuple that references the candidate, a reload or spill tuple (0x1B copy) is inserted there
  (`FUN_10724C87`).
* Edges between blocks of different regions get 0x1B copy tuples (spill stores, reloads): **piece
  boundaries sit on CFG edges and joins**. That is where the `jmp L / L': mov ebx,[h]` style reloads
  of the original come from.

So pieces are a function of *which candidates were coloured before this one lost its last register*.
Per-case "refs 1" pieces of a variable in a switch are a typical product: once a long-lived value takes
the last free register, every other value live across the switch is cut into per-case pieces.

### 3.9 Coalescing and rematerialisation are gated off here

The driver calls the copy-coalescing helper `FUN_107683E3`, and both `FUN_107169C9` and the colouring
routine call rematerialisation (`FUN_10768E10`, `FUN_10768492`), **only for candidates without flag 4
(`cand+5 & 4`)**. In a whole-TU trace of the KGT graphics code with `/Ox /Oa`, *every* candidate had
flag 4 set (flag bytes 0x05, 0x0D, 0x2D, 0x8D, 0xAD) and none of these routines was ever entered
(`dk28` hooks). In the decompilation, `FUN_1071431D` sets flag 4 for most kinds of reference. [E for
that TU; I that it holds for all `/Ox` code]

Practical meaning: **do not explain a VC6 output by rematerialisation or by the allocator's own
coalescing.** Copies are handled earlier (copy propagation in the optimiser) and through preferences
(3.10). Earlier notes that describe `FUN_107683E3` lowering a copy's priority describe the code, not
behaviour observed in this configuration.

### 3.10 Copy and hard-register preferences

`FUN_1071431D` records preferences with `FUN_10714F83` for assignment tuples (op 1) and op 0x12 when
the other operand is another candidate (kind 2) or a hard register (kind 1): the candidate prefers the
other side's register. Examples [E/O]:

* a call result (eax) assigned to a variable gives it a preference for eax (weights 1..4 seen);
* `i = X` where X is coloured earlier and dead after the copy: i takes X's register; if X stays live,
  i gets another register and both paths copy;
* a constant piece coloured before a copy target lets the target share the constant's register
  (`mov edi,ebx; imul edi`).

Preferences act in both directions through the cost function (3.7): they attract the candidate and
repel its uncoloured neighbours.

### 3.11 Constants and "constant register mode"

Frequently used constants (0, 1, 2, ...) are candidates, with id 0 and zero units per use, so their
priority comes only from the N_b structure [E]. Normally their webs are long and weak: when a strong
candidate takes the last register over them they lose it, go through the spill path and stay
immediates (a zero piece with benefit 0 is spilled, i.e. `xor` is not kept in a register).

In `vjmpHandleBattleInterface` a small change of statement order (`i = 0;` before two unrelated
assignments at the top of a loop preheader) flipped the whole function into a mode where the constants
0, 1 and 2 got registers over most of the function [E for the trace, I for the general statement]:

* at the first spill/split call, only 3 candidates lost their last register instead of 10, so the
  constant webs were cut into different pieces;
* a new 8-reference piece of the constant 2 had priority 86 and was coloured *before* the loop pieces,
  then it and a constant-1 piece grew back to the function entry;
* the zero-constant piece from the entry to the early `i = 0` got priority 3 / benefit 3 instead of
  -4 / 0, and ebx through a copy preference with `i`, giving `xor ebx,ebx / cmp eax,ebx` at the top.

Forcing constant pieces' priorities down did not undo it (the spill decision is the benefit). The
lesson: statement order near the top of a function can change which constants are "worth" a register
everywhere, with large code changes. If an original keeps a constant in a register, look for extra
uses in the same region (splitting `case A: case B:` into two identical cases adds a use that VC6
merges back later).

### 3.12 Calls, loops and strength-reduction temps

* A web that crosses a call can only be coloured with callee-saved registers; piece growth stops where
  a call leaves no allowed register. [E]
* Loop strength reduction introduces temps (e.g. `t = pTable` as the base of `pTable + i*42`). Their
  webs follow the same rules. In `bReadKgtCore` the original's temp spans the calls in the loop body,
  gets negative benefit, is split, and its entry piece becomes `mov ecx,eax` after the allocation
  call; ours ends at the first loop-head use, never crosses a call, gets benefit 2 and eax. Any extra
  `pTable`-based use after a call in the loop reproduces the original's allocation but costs
  instructions. [E for the mechanism, the original's source is not known]
* An escaped (address-taken) pointer is treated as killed by every call and every store through a
  pointer: it is reloaded at the loop top on each back edge. With only loads and scalar global stores
  in the body it is treated as invariant and the loop becomes a pointer induction variable. [O]

### 3.13 Register order summary

| situation | order |
|---|---|
| class order list, ties in the cost function | eax, ecx, edx, esi, edi, ebx, ebp |
| web crossing a call (caller-saved excluded) | esi, edi, ebx, ebp |
| ebp | only when the frame pointer is free; removed from the splitter's set when `DAT_107AC194` is 0 [I] |

---

## 4. Stack slot layout

From `FUN_10733AC7` and its callees, confirmed with `c2_nosort` / `c2_weights` and a simulator
(`sa15\stksim.py`) that reproduced the frames of test files exactly [E]:

1. **Weights.** A symbol's weight is the number of memory operands naming it in the code *at stack
   allocation time*: after register allocation, but before cross-jumping (tail merging) and before the
   peephole that turns a store+reload pair into a register move. Walk weights are therefore >= the
   counts you see in the final listing. The walk trace (`STK` lines) shows the extra references: e.g.
   four switch arms each with its own reload before they are merged.
2. **List order.** Symbols are listed by size ascending, then weight descending; equal weights keep
   the order in which the symbols *reached* that count during the walk (block order).
3. **Records.** Parameters get their records first. Each local, in list order, joins the **last**
   compatible record (size <= 2 x the record's, lifetimes not overlapping), else opens a new record.
   A shared record sits at its first member's list position; the first record is the lowest address
   (top of the frame, nearest `esp`).
4. **Large frames.** If the frame exceeds 0x80 bytes, local records are quicksorted (`FUN_10750F58`:
   Lomuto partition, middle pivot, *unstable*) by `weight * 1000 / size` descending. Equal keys come
   out permuted deterministically, so the pre-sort order still matters.
5. **Dead parameter slots.** Locals can reuse the slots of parameters that are dead, unless the frame
   is 0x70 bytes or larger.

Examples of what this explains:

* Swapped slots of two variables with equal final counts: look at the walk (pre-merge) weights and the
  reach order, not at the final listing (`vDrawCurrentEngineObject` pChar/pStep, both 13).
* A record's position is that of its first member: using a separate variable for one sub-use
  (`pPix8` in `iLoadExternalImage`) changed which symbol opened a shared record and fixed the slot
  order after the sort.
* An extra memory reference (e.g. one more reload of a pointer) moves that pointer ahead of another
  symbol with one reference fewer (`bReadKgtCore`).
* A frame growing past 0x70 (e.g. a new spilled temp) stops loop counters from reusing dead parameter
  slots and shifts everything (`vDrawKgtImage16`, `WORD a, inv`).
* Declaration order has no effect.

---

## 5. Expression canonicalisation (what the back end sees)

These results come from test compiles and traces rather than from decompiling the expression code;
they explain operand and term orders that no source rewrite seems to change.

* **Names, declaration order, spelling** (macros vs inline expressions, loop syntax, `x += y` vs
  `x = x + y`, operand order of commutative operators, extra parentheses, most casts) are normalised
  before allocation: identical IL, identical priorities. [O, across hundreds of variants]
* **Two conversion kinds.** Integer widening is either zero- or sign-extension; every other spelling
  (`(int)(unsigned)x`, `(DWORD)`, `(long)`, `& 0xFFFF`, `^ 0`, `(WORD)(short)x`) maps to one of them.
  [O]
* **Narrow multipliers.** A WORD->int conversion of a multiplication operand is dropped when only the
  low 16 bits of the product are needed (e.g. `(s >> 5) & 0x7E0`, `& 0x1F`, but not `& 0xF800`) *and*
  the conversion node has a single use after CSE. If the same `zext(a)` appears in several terms it is
  CSE'd into one temp and materialised once. Explicit truncation casts on products/sums are applied
  before CSE and remove the conversions outright. `int a = (WORD)field;` with plain uses narrows the
  *definition* (a 16-bit `mov si,[...]` load with no extension), where `WORD a` is extended once and
  shared. [O]
* **Term order of a sum** is canonical, not source order: terms are ranked by a weight that grows with
  the number of conversion nodes they contain; ties keep source order. A value-neutral cast such as
  `(short)x` on an operand whose high product bits are masked away raises a term's weight and moves it
  earlier. It is not the scheduler (`/G3`, `/G4`, `/G6` give the same order). [O]
* **Sums of pointer loads** (`*p0 + *p1 + *p2 + *p3`): the leaf order is the **reverse of the order in
  which the pointer variables are first assigned** in the function (declaration order irrelevant). For
  some masks (e.g. `& 0xE79C`, values >= 0xC000 in that test) the order is additionally rotated, by an
  amount that depends on context. Dead stores `p0 = 0; p1 = 0; p2 = 0; p3 = 0;` placed after the real
  uses change the ranking (they reproduced the original's order in `vDrawCurrentEngineObject`).
  [O; rotation unexplained]
* **Loops.** `for (y = 0; y < n; y++)` with y only a counter becomes a count-down loop; any `&&` in
  the condition keeps the up-counting form. [O]

---

## 6. Using this in practice

### 6.1 The workflow

1. **Localise the difference.** Aligned diff of your function vs the original; group it into regions
   (prologue, a loop, a case).
2. **Trace.** Compile a mini TU with a trace DLL and read the candidates involved in the region: ids,
   priorities per round, benefits, chosen registers, the cost arrays at the choice, the neighbours.
3. **Force.** Build a forced DLL and move one number (priority of one piece, benefit of one piece)
   until the region matches. Scan all ids if you have no idea (single-id scans, then coordinate
   descent). The result tells you *which allocator decision differs*: "the original colours X before
   Y", "the original's piece of j has benefit <= 0", "n must not see pTable's eax preference".
4. **Explain.** Use the trace hooks (per-block `BLK`/`H2` lines, benefit `H1` lines) to see which
   blocks or references produce the number you had to change.
5. **Find a source form** that changes exactly that quantity without changing the code, using the
   levers below; score many variants in parallel.
6. If nothing works, record the forced result and the decision in the project notes: the next person
   starts from the decision, not from scratch.

Forcing is a diagnostic only: never ship code that depends on a patched compiler. Also beware that a
forced decision can produce the original's code *by a different mechanism* than the original (a
forced E x-scroll temp fixed a slot swap but by adding real reloads).

### 6.2 Source changes and the quantity they move

| source change | what it changes inside c2 | status |
|---|---|---|
| dead address-taking, `if (0) vMemzero(&v, 0);` | removes `v` from the candidate set (always memory); shifts every later round | E |
| `*(volatile int *)&g` on each read of a global | removes the global's CSE candidate (reloaded at every use) | E |
| moving an assignment into a branch arm / `if (c) { x = e; goto L; }` form | new edge block: negative priority terms for candidates live there | E |
| real branch vs `if (0) goto L; L:;` | the empty boundary is not an RA block (priority-neutral), but it stops forward substitution and scheduling across it | E / O |
| per-case locals instead of shared function-level temps | cuts one web into independent webs (vBlit 90 -> 60) | O |
| separate variable for a sub-use | splits a web; changes stack record membership | E |
| statement order, first-assignment order | web start points, N_b of the top blocks, which constants' pieces form; leaf order of pointer-load sums | E/O |
| decoupling a dependency (`pSrc = base + x + 1` instead of `pSrc = base + nColors` with `nColors = x + 1`) | the variable loses the references in the other computation; its priority drops | O |
| dead stores / dead initialisers of real variables | add definitions; change reload order at joins, first-assignment rank, sometimes whole cascades | O |
| duplicating a statement into both arms / removing a switch fallthrough | extra references in more blocks (higher N_b terms); VC6 merges the copies back after allocation, so the code is unchanged | E |
| value-neutral casts (`(short)x` where high bits are masked) | term weight in canonical sums; narrowing of conversions | O |
| `int a = (WORD)field` vs `WORD a` | narrowed definition vs one shared extension | O |
| an extra use of a value after a call | web crosses the call, benefit can go negative, split pieces | E |
| `volatile` local | forces a stack slot and memory accesses for that value | O |
| taking the address without escape (`(void)&v`) | nothing | O |
| `register` keyword, declaration order, names | nothing | O |

A warning from `vDrawCurrentEngineObject`: in some functions *any* dead non-goto statement anywhere
(`if (0) rand();`) triggers a large register cascade. A lever that is neutral in one function can be
a knife-edge in another; always score the whole function.

### 6.3 Reading a trace, briefly

A composite example (lines from the `hb29` and `bi25` traces, shortened):

    FN _vHandleHitboxEffects
    INS _j        prio=68 id=683 idx=25 refs=5 ben=8
    SPL _j        prio=68 id=683 idx=25
    REG _j        idx=25 id=683 r=2              (ecx)
      NB _iH      id=675 idx=.. prio=.. avail=..  (allowed bits: 2/4/8 eax/ecx/edx, 0x10 ebx, 0x40 ebp, 0x80 esi, 0x100 edi)
    ASG _bGuard   prio=144 id=415 idx=105 ben=-48
    SPC n=3 dat=79

Read it as: `j`'s round-2 piece (5 references) has benefit 8, so it is coloured and gets ecx; bGuard's
piece carries reloads from earlier splits, benefit -48, spill path; a colouring emptied 3 neighbours
and the per-candidate splitter ran.

---

## 7. Open questions

* **`DAT_1079E88C`**: what it counts, and whether the global region splitter (>= 100) is ever used
  in real code.
* **`FUN_1078E7FE`**: exact role (the spill choice under block pressure is a guess), and the
  conditions of `FUN_1074C92B` / `FUN_10725131` (never entered in the traced functions).
* **Register class 1**: processed before class 0 by the driver; which registers or values it holds
  (byte registers?) was not looked at.
* **Flag 4 everywhere**: is rematerialisation/coalescing ever enabled in some other configuration
  (other flags, C++ code, floating point)?
* **Ids**: the exact rule assigning candidate ids (and so the tie-break) beyond "first-defined variable
  gets the larger id" in simple cases.
* **Units**: exact per-reference unit values from `FUN_10714EEB` / `FUN_107152C2` / `FUN_10714C76`
  for all operand kinds (the "2 per reference" rule is empirical).
* **Constant register mode**: a general predictor of when a small statement move flips constants into
  registers across a function.
* **Leaf-order rotation** in sums of pointer loads for large masks (`0xE79C` rotated by one, `0xFF9C`
  by two; depends on context, not on TU state). Looks hash- or id-like.
* **Scheduler ties decided by immediates**: in one case the `and` order of two terms depended only on
  the mask value (0xF800 vs 0x7C00), not on the source.
* **Unmatched decisions in KGT**, each isolated by forcing but without a source form found: the zero
  constant over the top of `vjmpHandleBattleInterface` staying spilled while `i` is live early; the
  strength-reduction temp of `bReadKgtCore` crossing calls with no extra reference; the loop counter
  piece in `vHandleHitboxEffects` needing benefit <= 0 (one more spill tuple or one fewer +8 use);
  `vDrawKgtImage16` case 4 needing G and B before R and `a` spilled at its definition;
  iOtherX/iOtherY piece order in `vHandleHitboxEffects` although the IL of the arms is identical.
  These all suggest that the original source differed in ways that change piece extents (earlier
  splits, spill tuples inherited by pieces) rather than in the obvious places.
