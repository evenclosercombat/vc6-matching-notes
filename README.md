# Matching Visual C++ 6.0 output: notes

What we learned about Microsoft Visual C++ 6.0 while writing C source that recompiles, byte for byte,
into a shipped 2002 Windows game (`KGT2nd_GAME.exe`, the runtime of *2D Fighter Maker 2nd*; project:
the `kgt2nd_decomp` repository next to this one). The notes are written for anyone - people or coding
agents - doing the same with another VC6 binary: how the compiler and linker behave, which source
changes move which part of the output, and how to find out why a function does not match.

Everything here was established on **VC6 RTM** (`cl` 12.00.8168, `c2.dll` of that build, `link`
6.00.8168, `cvtres` 5.00.1720) with the flags `/Ox /Oa /W3`, 32-bit x86, statically linked `LIBC.LIB`.
Other service packs may differ in details. Examples name functions of the KGT project; the principles are
general.

| file | contents |
|---|---|
| [toolchain.md](toolchain.md) | identifying the compiler, flags, CRT and link setup of a binary; running VC6 on current Windows |
| [compiler-behaviour.md](compiler-behaviour.md) | how `cl` lays out data and code: literals, `.bss`, block layout, switches, loops, tail merging |
| [register-allocation.md](register-allocation.md) | the practical rules of VC6's register and stack-slot allocation |
| [c2-internals.md](c2-internals.md) | the back end (`c2.dll`) reverse-engineered: allocator internals, function map, instrumentation |
| [matching-techniques.md](matching-techniques.md) | source changes that move the output ("levers"), workflow, tooling, keeping a build matching |
| [linker-and-postlink.md](linker-and-postlink.md) | LINK 6.00 behaviour (import table order, communal variables, OMF objects, Rich header) and post-link artefacts |

## Reference implementations

The `kgt2nd_decomp` repository has working versions of the tools these notes describe (Python, run
against its own build, but easy to adapt):

| tool | what it shows how to do |
|---|---|
| `tools/check.py`, `tools/objdis.py`, `tools/origdis.py` | compile a TU and compare each function with the original; disassemble either side |
| `tools/tryvar.py` | score many OLD/NEW source variants of one function in one run |
| `tools/permuter/perm.py`, `fscore.py` | random and behaviour-preserving (`--safe`) source search; aligned-instruction scoring with relocations resolved from the linker map |
| `tools/asmfunc.py` | turn an unmatched function into a byte-exact stand-in and back |
| `tools/mklink.py` | the LINK.EXE copy with the classic `qsort` |
| `tools/gen_game_bss.py` + `asm/game_bss.txt` | uninitialized data laid out explicitly in an assembler object |
| `tools/postlink.py`, `tools/fix_res.py` | the post-link and resource-compiler artefacts |
| `tools/mapcmp.py`, `tools/verify.py` | whole-executable checks |

## The short version

* Get the **flags and CRT** right first (see toolchain.md); nothing else matters until string literals,
  `.data` and the CRT line up.
* **Structure before registers**: make the function the right size with the right block order, then chase
  register and stack-slot differences.
* Registers and stack slots are decided on **live ranges and control flow**, not on names, declaration
  order or spelling. Names never matter; spelling (casts, macros, operator order, loop syntax) is mostly
  normalised away. What changes the result: where values are defined and used, which values are live at
  the same time, block boundaries, and which variables live in memory.
* When a difference resists, **instrument the compiler** (c2-internals.md): force one allocator decision
  in a patched copy of `c2.dll` to learn which decision differs, then look for a source form that makes
  the compiler take it by itself.
* Keep a **byte-exact build at all times** by standing in the original machine code for functions that do
  not match yet (matching-techniques.md), so the rest of the program can be verified by a hash.
