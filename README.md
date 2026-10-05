# Volley
A fast replacement for curl, wget and git

## Note

This project is **not** affiliated with, endorsed by, or related to
[google/volley](https://github.com/google/volley), the Android HTTP networking
library. It is an independent command-line HTTP client and git porcelain written
in C, and shares no code with that project.

## Install

### From the release tarball

```sh
tar -xJf volley-1.0.0.tar.xz
cd volley-1.0.0
./configure
make
sudo make install
```

`make install` places:

| Path | Contents |
| --- | --- |
| `$PREFIX/bin/volley` | the CLI |
| `$PREFIX/include/libvolley.h` | library header |
| `$PREFIX/lib/libvolley.a` | static library |
| `$PREFIX/lib/libvolley.so.1.0.0` | shared library, plus `libvolley.so.1` and `libvolley.so` symlinks |

It runs `ldconfig` on the library directory when possible, so the shared library
is picked up without setting `LD_LIBRARY_PATH`.

### Install options

`configure` accepts:

```
./configure [--prefix=DIR] [--cc=CMD] [--cflags=...] [--ldlibs=...] [--static-libs]
```

Then `sudo make install PREFIX=/usr/local`, or stage a package build with
`make install DESTDIR=/tmp/pkg PREFIX=/usr`.

### Build dependencies

Debian/Ubuntu:

```sh
sudo apt install build-essential libssl-dev zlib1g-dev
```

Fedora/RHEL:

```sh
sudo dnf install gcc make openssl-devel zlib-devel
```

Alpine:

```sh
sudo apk add build-base openssl-dev zlib-dev
```

macOS (Homebrew):

```sh
brew install openssl@3 zlib
```

Volley needs a C compiler, OpenSSL, zlib, and pthreads. Nothing else.

### Linking against libvolley

Static:

```sh
cc -o myapp myapp.c -I/usr/local/include /usr/local/lib/libvolley.a \
   -lssl -lcrypto -lz -pthread
```

Shared:

```sh
cc -o myapp myapp.c -I/usr/local/include -L/usr/local/lib -lvolley \
   -lssl -lcrypto -lz -pthread
```

Or skip the manual flags and build against the installed copy:

```sh
./configure --prefix=/usr
make
sudo make install
sudo ldconfig        # if PREFIX/lib is not on the loader path
```

### Uninstall

There is no `make uninstall` target. Remove the installed files by hand:

```sh
sudo rm -f /usr/local/bin/volley \
           /usr/local/include/libvolley.h \
           /usr/local/lib/libvolley.a \
           /usr/local/lib/libvolley.so*
```

## Build

```sh
./configure && make
```

Produces the `volley` CLI plus `libvolley.a` / `libvolley.so`. `make check` runs
the offline test suite (boots a local test server, no network required);
`make test` adds best-effort online gates. `make clean` removes build artifacts.

## HTTP features

Protocols and transport
- HTTP/1.1 and HTTP/2 over TLS via ALPN (`--http2`, `--http11` to force 1.1)
- FTP (RFC 959) and GOPHER (RFC 1436)
- SOCKS5 and SOCKS5h proxies, HTTP proxies, proxy credentials (`-x`, `-U`)
- mTLS client certificates (`--client-cert`, `--client-key`)
- Transparent gzip/deflate decoding (`--no-encoding` to disable)
- IPv4/IPv6 forcing (`-4`, `-6`), insecure TLS (`-k`)

Requests
- Any method (`-X`), repeatable headers (`-H`), POST data (`-d`, `&`-joined)
- Multipart forms (`-F name=value` or `name=@file`)
- File upload (`-T`) and chunked streaming uploads (`--chunked`)
- Basic auth (`-u`), `.netrc` (`--netrc`), wgetrc-style config files (`-K`)

Cookies and sessions
- Cookie strings and cookie files (`-b`), Netscape cookie jars (`--cookie-jar`)
- `--junk-session-cookies` to keep session cookies out of the jar
- Persistent per-host sessions (`-S name`) storing headers and cookies across runs

Downloads
- Output to file (`-o`) or remote filename (`-O`), headers only (`-I`)
- Byte ranges (`-r`), segmented parallel download via Range (`-c`)
- Resume (`-C`, `-` for file size), parallel URLs (`-j`)
- Rate limiting (`--limit-rate`), progress meters (`--progress bar|dot`)

Crawling
- Recursive fetch (`--recursive`) and mirror mode (`--mirror`) for HTML and CSS
- Depth control (`--level`), host scoping (`--domains`), `--span-hosts`
- Include/exclude patterns (`--accept`, `--reject`)
- FTP directory listing (`-l`, NLST)

Reliability and output
- Retries (`--retry`, `--retry-all-errors`, `--retry-delay`)
- Timeouts (`--max-time`, `--connect-timeout`)
- Redirect control (`-L` default, `--no-location`)
- Response headers in output (`-i`), verbosity (`-v`), silence (`-s`)
- Exit non-zero on HTTP errors (`-f`), color mode (`--color`)
- Custom User-Agent (`-A`), version (`-V`), help (`-h`)

## Git features

No external `git` binary required. Commands accept `-C <dir>` / `--git-dir <dir>`.

- `volley clone <git-url> [dir]` — smart-HTTP clone into a working repository
- `volley ls-remote <url> [ref...]` — list a remote's advertised refs
- `volley init [dir]` / `volley init --bare` — create an empty repository
- `volley branch` / `volley tag` — list local branches or tags
- `volley remote [-v]` / `volley remote add <name> <url>` — inspect or add remotes
- `volley rev-parse <ref>...` — resolve HEAD, branches, tags, remotes to object IDs
- `volley cat-file -t|-p|-s <obj>` — object type, content, or size
- `volley log [<n>] [<ref>]` — oneline commit history
- `volley ls-tree [<treeish>]` — pretty-print a tree

## Library API

Link against `libvolley.a` or `libvolley.so` to embed the same engine:

```c
#include "libvolley.h"

struct volley_result r;
char err[256];

volley_global_init();
if (volley_get("https://example.com", &r, err, sizeof err) == 0)
        printf("%d\n", r.status);
else
        fprintf(stderr, "%s\n", err);
volley_result_free(&r);
volley_global_cleanup();
```

- Lifecycle: `volley_global_init`, `volley_global_cleanup`, `volley_version`
- URL parsing: `volley_parse_url`, `volley_url_free`
- Fetching: `volley_fetch`, `volley_get`, `volley_head`, `volley_result_free`
- Git: `volley_git_clone`
- Utilities: `volley_gzip_inflate`, `volley_b64_encode`, `volley_b64_decode`
- Large downloads: `volley_large_fetch` streams to disk in O(1) memory and
  validates `Range`/`Content-Range` on resume
- Errors: `volley_last_error`, `volley_error_clear`

## How it competes with curl, wget and git

Versus curl
- Faster startup and lower memory: one small static-linked-style binary in C, no
  heavy dependency tree beyond OpenSSL and zlib
- Ships a git client in the same binary, so scripts that fetch and then clone do
  not need two tools
- Built-in recursive HTML/CSS crawling (`--recursive`, `--mirror`) with depth,
  domain and pattern controls, which curl does not provide
- Embeddable as a library, not just a CLI
- Trade-off: curl has a much larger protocol surface (IMAP/POP3/SMTP, more TLS
  cipher configuration, IDN edge cases) and a far bigger test matrix

Versus wget
- Parallel segmented downloads (`-c`) and multi-URL parallelism (`-j`) with
  built-in rate limiting
- Single tool for HTTP, FTP, GOPHER, SOCKS5 and git, where wget covers HTTP/FTP
- mTLS, HTTP/2, chunked uploads and persistent sessions are available in the same
  binary
- Trade-off: wget's recursive mirroring and FTP support are more mature and have
  many more years of edge-case handling

Versus git
- `clone`, `init`, `branch`, `tag`, `remote`, `rev-parse`, `cat-file`, `log`,
  `ls-tree` and `ls-remote` without installing git
- Useful in minimal containers, CI images and embedded environments where git and
  its dependencies are unavailable or unwanted
- Deliberately scoped to the porcelain commands above: no commit, push, fetch,
  merge, rebase, index handling, packfile reading, hooks, or worktree
  operations. Local object reading covers loose objects, which is what `clone`
  writes, so packfile-backed repositories from other tools are not read
- Use real git for anything beyond read-only inspection and cloning

In short: volley is not a drop-in replacement for any of the three. It is a
single fast binary that covers the common cases — fetch, download, crawl, and
clone — when carrying three tools and their dependencies is not worth it.