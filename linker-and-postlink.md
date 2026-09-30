# LINK 6.00 and post-link artefacts

Once every function matches, the remaining differences are in the layout LINK produces and in what
happened to the file after linking. These are the behaviours that mattered.

## Object order and sections

* LINK places each section's contributions in the order the objects are given on the command line, the
  CRT library's objects after the game's. Getting the object list and order right puts every function at
  its original address; a linker map compared against the original's function addresses shows a wrong
  function size as a jump in the running address delta.
* Functions of one object stay in source order.
* The **Rich header** records the tools and object counts (toolchain.md); an object's position also matters
  there (the C++ stand-in had to be linked before at least one C object).
* An **empty export directory** with a DLL-style name ("exe.exe") comes from linking with a `.def` file
  containing an empty `EXPORTS` section; the name is the project's output name at the time.

## Uninitialized data

* `.bss` = each object's `.bss` in link order, then the **communal variables** (`int x;` at file scope in C
  without `static`, or `COMDEF` in OMF). LINK allocates communal variables after all `.bss` sections,
  pushing each newly seen one to the front of its list: they come out in reverse order of first sight.
  Each is aligned to min(next power of two >= size, 32).
* Because `cl` orders a TU's own `.bss` and communals by a name hash (compiler-behaviour.md), the practical
  way to reproduce an original layout is to define **all** uninitialized globals in one assembler object:
  ordinary `_BSS` storage for the plain part (in original order) and communal definitions for the rest (in
  reverse order), with a table of address/size/name checked against the linker map. C code declares them
  `extern`.
* An OMF object's `_BSS` is padded to 16 bytes. If the original's last few bytes of game `.bss` belong to
  another object, keep a small `static` in the last C object to reproduce that.
* All-zero string literals (`""`) are 1-byte `.bss` contributions of their TU and can sit in the middle of
  the uninitialized data; refer to laid-out slots instead of writing `""` if their position can't be
  reproduced otherwise.

## Import tables

* **IAT order**: LINK sorts the `.idata$4/$5` contributions with the C runtime's `qsort`, comparing only the
  DLL names. The order of one DLL's thunks is therefore whatever permutation `qsort` leaves equal elements
  in - an implementation detail of msvcrt.dll. Windows Vista and later ship a different `qsort` than 2002's,
  so the stock LINK 6.00 produces a different IAT order (and different `call [__imp__...]` operands) on a
  current system. Fix: a copy of `LINK.EXE` with one extra section containing `qsort.obj` from VC6's own
  `LIBC.LIB` and its `call [__imp__qsort]` instructions redirected there (the bound import directory has to
  go to make room for the extra section header).
* **Hint/name table order** is the order in which the objects' symbol tables first reference each import;
  a compiler's symbol table lists externals in reverse order of first use in the TU. Dead code (an
  `if (0)` body) still references its imports, which is why stand-ins keep the dead body.

## Post-link artefacts seen in a shipped binary

Check the finished original for signs of tools run after LINK:

* **Timestamps**: LINK stamps the link time in the file header and export directory; reproduce the
  original's value explicitly.
* **Resources rewritten with `UpdateResource`** (resource directory stamps later than the link time are the
  clue). `UpdateResource` lays out `.rsrc` differently from CVTRES (directory tables breadth-first, then data
  entries, name strings, data 4-byte aligned), leaves an extra empty section header behind the resource
  section (".uro\x07", 1 byte virtual size, no raw data, with leftover garbage in some header fields),
  updates `SizeOfImage` but not the checksum. So the checksum is LINK's value for the *pre-update* image
  (`/RELEASE`), which can't be recomputed without the original resources: take it from the original.
* **Section flags** that LINK cannot produce: here `.rdata` was marked writable (LINK only merges `.edata`
  into `.rdata` when their attributes agree, so a writable `.rdata` with an export directory inside it must
  have been patched later).

A post-link script that rebuilds `.rsrc` in `UpdateResource`'s layout from the resources LINK produced,
adds the stray header, and patches the stamps, checksum and flags keeps the repository free of any bytes
copied from the original.
