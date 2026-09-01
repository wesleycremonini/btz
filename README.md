# btc-crawler

A Zig project. Currently a hello-world scaffold.

## Requirements

- Zig `0.16.0` (pinned in [`.zigversion`](.zigversion) and `build.zig.zon`'s `minimum_zig_version`)

## Build & run

```sh
zig build run              # debug build
zig build --release run    # ReleaseSafe build
```

The compiled binary is written to `zig-out/bin/`.

## Test

```sh
zig build test
```

## Format

```sh
zig fmt .          # rewrite
zig fmt --check .   # verify, non-zero exit on diff (used in CI)
```

## Layout

| Path                        | Purpose                          |
| --------------------------- | -------------------------------- |
| `src/main.zig`              | Executable entry point           |
| `build.zig`                 | Build graph: `run`, `test` steps |
| `build.zig.zon`             | Package manifest                 |
| `.github/workflows/ci.yml`  | fmt check, build, test on CI     |

## License

[MIT](LICENSE) © Wesley Cremonini
