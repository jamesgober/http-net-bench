# Vendored sources

Everything here is third-party source, kept byte for byte, so that a results file names exactly what ran. None of it is http-net: http-net always comes from crates.io.

| Directory | What | Origin | License |
|---|---|---|---|
| `picohttpparser/` | `picohttpparser.c`, `picohttpparser.h` | [h2o/picohttpparser](https://github.com/h2o/picohttpparser) master, commit `dd573d8fa9264c646a400e96ce9f07dea6f156e4` (2026-10-27), the commit http-net's `docs/PARITY.md` was checked against | MIT or Perl, at your option; the terms are in the file headers (the project has no separate license file) |
| `llhttp/` | `api.c`, `http.c`, `llhttp.c`, `llhttp.h`, `LICENSE`, `LICENSE-MIT` | [nodejs/llhttp](https://github.com/nodejs/llhttp) release tag `release/v9.4.3` (2026-07-30), the generated C of the release branch, from `src/` and `include/` | MIT |
