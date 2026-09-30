# Toolchain: identifying and reproducing the build setup

## Read the Rich header first

The undocumented "Rich" header between the DOS stub and the PE header lists, for every tool that
contributed objects, its product id, build number and object count. For KGT2nd_GAME.exe it said:

* 13 C objects and 1 C++ object from `cl` 12.00.8168 (VC6 RTM; service packs have higher build numbers),
* 1 object converted from OMF (`Cvtomf` 6.00): a hand-written assembler module,
* import-library objects from `Linker512` 8034 (the VC6 import libs),
* the objects of the static CRT (`LIBC.LIB`: 44 C objects, one C++ object, 11 MASM objects),
* `link` 6.00.8168 and `cvtres` 5.00.1720.

That fixes the compiler build, the number of translation units (and hence how the source was split), the
fact that one TU was C++ (it contributed nothing visible; an empty `.cpp` file reproduces its Rich entry),
and the presence of a non-C object. The Rich header's size also moves `e_lfanew`, so the object mix has
to be exact before the PE header can match (0xF0 here).

## Compiler flags

* **`/Ox /Oa`**, not `/O2`. `/O2` is `/Ox` plus `/GF` (pool identical string literals into read-only
  COMDATs) and `/Gy` (function-level linking). The original had duplicate identical literals, 4-byte
  aligned, all in `.data`, so neither was on. Code generation is otherwise identical between the two.
* **`/Oa`** (assume no aliasing) is visible in the code: loads are hoisted above stores through pointers,
  for example above an inlined `strcpy`'s `rep movsb`. Without it those loads stay after the store.
* `/W3` does not affect code; it is listed because the original project most likely used the defaults of
  a VC6 "Release" configuration.
* No `/GX`, no `/GR`, no debug information, and the default static single-threaded CRT (`/ML`,
  `LIBC.LIB`).

How to confirm a guess: compile one small, already-matched function with the candidate flags and compare
with `objdis`-style disassembly; then compare the whole `.data` of a TU (literal order and alignment are
very sensitive to `/GF`).

## CRT

* Link a stub program with `LIBC.LIB` and compare the CRT part of the executable (from the entry point on)
  with the original: with the right CRT the functions line up byte for byte, which also pins where the
  game's objects end.
* `WinMain` versus `wWinMain`: defining `wWinMain` silently selects the Unicode startup code
  (`GetCommandLineW`, ...) and drops the multibyte code-page support, so the CRT part changes size.
* The CRT's `.bss` and communal variables come after the game's; the game's must end at the right address
  (see linker-and-postlink.md).

## The non-C object

An object converted from OMF (`Cvtomf` in the Rich header) means an assembler module built with an
assembler that produced OMF (MASM 6 or older in OMF mode, or TASM). It can be reproduced with **JWasm**
(`-omf`) or **NASM** (`-f obj`; LINK prints warning LNK4033 while converting and links fine). It also
changes link-level details: its `_BSS` is padded to 16 bytes, and a conversion leaves an extra empty
section behind (see linker-and-postlink.md).

## Running VC6 on current Windows

* `CL.EXE` may be marked "run as administrator" in the per-user AppCompat registry keys, which makes it
  fail when started from a script. Set the environment variable `__COMPAT_LAYER=RunAsInvoker` for the
  build instead of changing the registry.
* LINK 6.00 uses msvcrt.dll's `qsort`, which changed in Windows Vista; on current Windows the import
  address table comes out in a different order. Fix: a copy of `LINK.EXE` that calls the classic `qsort`
  from VC6's own `LIBC.LIB` (details in linker-and-postlink.md). Never modify the installed tools - make
  patched copies in the build directory.
* RC 5.00 (VC6's resource compiler) differs from later ones in two ways that can matter when the original's
  resources were compiled with a newer RC: VERSIONINFO block lengths (the newer RC counts the padding after
  a block's last child) and U+0000 characters inside dialog texts (RC 5.00 truncates). Post-process the
  `.res` if the original shows the newer behaviour.
* The compiler back end can be replaced per invocation with `cl /B2<path to c2.dll copy>`, which is how
  instrumented copies are used (c2-internals.md).
