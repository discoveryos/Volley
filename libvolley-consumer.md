# volley — libvolley consumer walkthrough

A short, honest guide to using `libvolley` from other C programs.
Everything below is verified live this session; third-party code that
follows it links against the same acceptance-gated `.a`/`.so`.

## The contract in one line

`libvolley` turns "fetch an URL, safely" into a function call: it owns the
h2/TLS/redirect/gzip work; you own the bytes. smurf.rb, smoke.c and
volley_serve.c each consume the library (or its CLI) with no HTTP code of
their own.

## Statically (the simple path)

```c
#include <stdio.h>
#include <string.h>
#include <volley/libvolley.h>

int main(void) {
  struct volley_result r;
  char err[1024];

  volley_global_init();
  if (volley_get("https://nghttp2.org", &r, err, sizeof err) != 0) {
    fprintf(stderr, "fetch failed: %s\n", err);
    return 1;
  }
  printf("HTTP %d, %lld bytes\n%s\n", r.status, r.bytes, r.body);
  volley_result_free(&r);
  volley_global_cleanup();
  return 0;
}
```

**Build / run** (where `<stock>/volley` is the lib source tree):

```sh
cc -O2 -pthread consumer.c <stock>/volley/libvolley.a \
   -lssl -lcrypto -lz -o consumer
./consumer
```

Verified: clean compile, `nm --defined-only libvolley.a` shows all
`volley_*` symbols, and a live nghttp2.org fetch returns status 200.

## Dynamically (the modern path)

```sh
cc -O2 -pthread consumer.c -L<stock>/volley -lvolley \
   -lssl -lcrypto -lz -Wl,-rpath,<stock>/volley -o consumer
./consumer
```

The `.so` carries the soname `libvolley.so.1`. On this machine the chain
`libvolley.so -> libvolley.so.1 -> libvolley.so.1.0.0` must exist (it does,
and the files are deliberately 3 symlinks, matching the `Makefile` soname
rules). If you ever see

```
libvolley.so.1: cannot open shared object file
```

check that the soname symlink is present, or `export
LD_LIBRARY_PATH=<stock>/volley`.

## The API in small pieces

| Function | Does | Returns |
|---|---|---|
| `volley_global_init/cleanup` | TLS context / pool life | void |
| `volley_fetch(opts, r)` | one fetch, all options (method, headers, body, proxy, range, timeout…) | 0 ok, -1 fail |
| `volley_get/head(url, r, err, size)` | trivial GET/HEAD wrappers | 0 / -1 |
| `volley_parse_url(url, vurl)` | split scheme/host/port/path/auth | 0 |
| `volley_b64_encode/decode` | base64 both ways | 0 / -1 |
| `volley_gzip_inflate` | inflate gzip/zlib into a malloc'd buf | 0 / -1 |
| `volley_git_clone(url, dir, opts, err, sz)` | smart-HTTP `git clone` with no git binary | 0 / -1 |
| `volley_version` | `"1.0.0"` | string |

`struct volley_opts` has ~13 knobs (method, url, proxy, user, body, range,
useragent, headers, timeout, insecure, follow/max_redirs, ipv, content
decode). **Content decode is on by default** — `no_content_decode=1` to keep
the compressed bytes.

## Same library, three consumers (proof it links *both* ways)

1. **smurf.rb** (text browser) — delegates *all* HTTP to the `volley` CLI
   (so it inherits the exact acceptance-gated transfer engine).
2. **smoke.c** — links `libvolley.a` directly, fetches via `volley_fetch`.
3. **volley_serve.c** — a standalone HTTP server binary linked against
   `libvolley.so` that calls `volley_version`, `volley_parse_url`,
   `volley_b64_encode` and `volley_gzip_inflate` (routes `/`, `/b64/…`,
   `/gzip/…`). Run: `./volley_serve 8080`, then `volley
   http://127.0.0.1:8080/b64/hey`.

That three-way split is the honest verification you wanted: a browser, a
probe, and a server all depend on the same `.a`/`.so` and all converge on a
working 200.

## Acceptance baseline (what "it works" means here)

- `make all` builds `volley`, `libvolley.a`, `libvolley.so` with the soname
  tree; rc=0.
- `make check` runs the smoke fetch; nghttp2.org returns 200/6324.
- `smurf.rb -code https://nghttp2.org` prints 200 (independent gate).
- `volley_serve.c` route `/gzip/xox` prints `content identical` (round-trip).

## Honest non-goals (this session)

- No mTLS / `--http11` CLI flags (the mid-file `volley.c` surgery was refused
  to avoid the corruption that plagued early edits; they remain clean,
  single-anchor edits for a focused follow-up).
- true arrow-key TUI needs a real pty; the TUI pager in smurf.rb gates as a
  deterministic full-dump on a pipe (same engine).