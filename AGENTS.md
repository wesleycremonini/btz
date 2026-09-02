# Agent instructions

Instructions for any AI coding agent working in this repo.

## TigerStyle is mandatory

All code here follows [`TIGER_STYLE.md`](TIGER_STYLE.md). Read it before writing
or changing code and treat it as binding. The rules that come up most often, all
already enforced in `src/`:

- **Naming.** `snake_case` for functions, variables, and files. Do not
  abbreviate — spell it out: `header` not `hdr`, `command` not `cmd`, `offset`
  not `off`, `return_code` not `rc`. Acronyms keep their casing (`VSRState`).
  The one exception is a primitive integer used as a sort/matrix argument.
- **Assertions.** Assert preconditions, postconditions, and invariants
  generously; pair bounds checks. Use `comptime` blocks to pin layout and size
  relationships. A function with a single `assert` is under-asserted.
- **Memory.** No allocation after startup. Buffers live in caller-owned structs
  and are passed in; functions fill through an out-pointer rather than returning
  heap data.
- **Control flow.** Every loop has a fixed upper bound and asserts on
  exhaustion. No unbounded `while`. Prefer a positive condition.
- **Types.** Fixed-width integers for wire data and counts (`u32`, not `usize`);
  exhaustive `switch` over ranges and enums; concrete error sets, never
  `anyerror`.
- **Scope.** Declare variables at the smallest scope, compute them close to
  where they are used, and don't alias them.

When TigerStyle and a convenient shortcut conflict, follow TigerStyle.

## Zig version

Target **Zig 0.16.0**, pinned in `.zigversion` and `build.zig.zon`'s
`minimum_zig_version`. Zig's `std`, build-system API, and syntax shift between
releases and model training data is usually stale — verify API shapes against
the installed `lib/std/` source or the 0.16.0 docs rather than memory. Flag any
spot where you are unsure an API matches 0.16.0 instead of guessing.

## Before you finish

Run all three and make sure they pass:

```sh
zig build
zig build test
zig fmt --check .
```

## Commits

No AI-attribution trailers (`Co-Authored-By:`, `Generated with…`, etc.).
Write descriptive commit messages: what changed and why, in the imperative mood,
following the style of the existing `git log`.
