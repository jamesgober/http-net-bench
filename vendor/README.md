# Vendored sources

Everything here is third-party or sibling source, kept byte for byte except where this file says otherwise, so that a results file names exactly what ran. None of it is http-net: http-net always comes from crates.io.

| Directory | What | Origin | License |
|---|---|---|---|
| `picohttpparser/` | `picohttpparser.c`, `picohttpparser.h` | [h2o/picohttpparser](https://github.com/h2o/picohttpparser) master, commit `dd573d8fa9264c646a400e96ce9f07dea6f156e4` (2026-10-27), the commit http-net's `docs/PARITY.md` was checked against | MIT or Perl, at your option; the terms are in the file headers (the project has no separate license file) |
| `llhttp/` | `api.c`, `http.c`, `llhttp.c`, `llhttp.h`, `LICENSE`, `LICENSE-MIT` | [nodejs/llhttp](https://github.com/nodejs/llhttp) release tag `release/v9.4.3` (2026-07-30), the generated C of the release branch, from `src/` and `include/` | MIT |
| `serve-net/` | `src/`, license files | [serve-net 0.3.0](https://crates.io/crates/serve-net/0.3.0) from crates.io (commit `dae0c86`) | MIT or Apache-2.0 |

## Why serve-net is vendored

serve-net 0.3.0 on crates.io requires `http-net = "0.6"`, and H6 must measure the http-net these benches measure, 0.9.x from crates.io. A `[patch]` cannot bridge two incompatible 0.x versions, so this copy changes that one requirement. The `src/` tree is the published code with no edit, and it compiled against http-net 0.9.0 unchanged.

`Cargo.toml` here is not the published manifest. It is reduced to the package, the library, the `http1` feature, and two dependencies:

- `http-net`: `"0.9"`, where upstream has `"0.6"`.
- `net-io`: `"0.3"`, as upstream.

The tests, benches, and examples of the crate, and their dev-dependencies, are left out; the build needs none of them.

When a published serve-net depends on http-net 0.9, drop this directory and use the crates.io version.
