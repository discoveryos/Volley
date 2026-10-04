# volley - a curl-like HTTP/2 client + library (no curl, libcurlless).
#
# One C file, three artifacts (source lives in src/):
#   volley          CLI client
#   libvolley.a     static library
#   libvolley.so    shared library (soname libvolley.so.1)
# plus a pair of consumer examples (smoke, volley_serve) and a test harness
# (check_api) used by `make check`.
#
#   ./configure              probe deps and write config.mk   (optional)
#   make                     build the three artifacts
#   make check               self-contained offline test battery
#   make test                check + online gates (needs network)
#   make install [PREFIX=…]  install under PREFIX (default /usr/local)
#   make clean               remove build products

-include config.mk

CC       ?= cc
CFLAGS   ?= -O2 -Wall -Wextra
CPIC     ?= -fPIC
CPTHREAD ?= -pthread
LDLIBS   ?= -pthread -lssl -lcrypto -lz
PREFIX   ?= /usr/local

SO_MAJOR  = 1
SO_MINOR  = 0
SO_BUILD  = 0
SO_RLS    = $(SO_MAJOR).$(SO_MINOR).$(SO_BUILD)
SONAME    = libvolley.so.$(SO_MAJOR)

SRCDIR = src
LIBDIR = $(PREFIX)/lib
INCDIR = $(PREFIX)/include

# check uses a private local server on 127.0.0.1
PORT = 18765
BASE = http://127.0.0.1:$(PORT)

all: volley libvolley.a libvolley.so

volley: $(SRCDIR)/volley.c $(SRCDIR)/libvolley.h
	$(CC) $(CFLAGS) $(CPTHREAD) -o $@ $(SRCDIR)/volley.c $(LDLIBS)

# The library objects are compiled with -DVOLLEY_LIB so main() and the whole
# CLI-only region is excluded: the .a/.so contain only the engine + public
# API, which is what lets smoke/volley_serve/check_api link cleanly.
libvolley.a: $(SRCDIR)/volley.c $(SRCDIR)/libvolley.h
	$(CC) $(CFLAGS) $(CPIC) $(CPTHREAD) -DVOLLEY_LIB -c -o volley_pic.o $(SRCDIR)/volley.c
	ar rcs $@ volley_pic.o
	ranlib $@

libvolley.so.$(SO_RLS): $(SRCDIR)/volley.c $(SRCDIR)/libvolley.h
	$(CC) $(CFLAGS) $(CPIC) $(CPTHREAD) -DVOLLEY_LIB -shared \
	    -Wl,-soname,$(SONAME) -o $@ $(SRCDIR)/volley.c $(LDLIBS)
	ln -sf $@ libvolley.so.$(SO_MAJOR)
	ln -sf $@ libvolley.so

libvolley.so: libvolley.so.$(SO_RLS)
	ln -sf $< $@

# --- consumer examples / test harness -------------------------------

smoke: $(SRCDIR)/smoke.c libvolley.a
	$(CC) $(CFLAGS) $(CPTHREAD) -I$(SRCDIR) -o $@ $(SRCDIR)/smoke.c libvolley.a $(LDLIBS)

volley_serve: $(SRCDIR)/volley_serve.c libvolley.a
	$(CC) $(CFLAGS) $(CPTHREAD) -I$(SRCDIR) -o $@ $(SRCDIR)/volley_serve.c libvolley.a $(LDLIBS)

check_api: $(SRCDIR)/check_api.c libvolley.a
	$(CC) $(CFLAGS) $(CPTHREAD) -I$(SRCDIR) -o $@ $(SRCDIR)/check_api.c libvolley.a $(LDLIBS)

gittest: $(SRCDIR)/gittest.c
	$(CC) $(CFLAGS) $(CPTHREAD) -o $@ $(SRCDIR)/gittest.c $(LDLIBS)

# --- install --------------------------------------------------------

install: all
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(LIBDIR) $(DESTDIR)$(INCDIR)
	install -m 755 volley $(DESTDIR)$(PREFIX)/bin/volley
	install -m 644 $(SRCDIR)/libvolley.h $(DESTDIR)$(INCDIR)/libvolley.h
	install -m 644 libvolley.a $(DESTDIR)$(LIBDIR)/libvolley.a
	install -m 755 libvolley.so.$(SO_RLS) $(DESTDIR)$(LIBDIR)/libvolley.so.$(SO_RLS)
	ln -sf libvolley.so.$(SO_RLS) $(DESTDIR)$(LIBDIR)/libvolley.so.$(SO_MAJOR)
	ln -sf libvolley.so.$(SO_RLS) $(DESTDIR)$(LIBDIR)/libvolley.so
	-@ldconfig $(DESTDIR)$(LIBDIR) 2>/dev/null || true

# --- tests ----------------------------------------------------------

# check: fully self-contained (no network). Builds everything, boots the local
# volley_serve on 127.0.0.1:$(PORT) and runs CLI + library assertions.
check: all smoke check_api volley_serve chk_syntax gittest
	@rm -rf check_tmp && mkdir -p check_tmp
	@echo "== volley serve on 127.0.0.1:$(PORT) =="
	@./volley_serve $(PORT) >/dev/null 2>&1 & \
	  SRV=$$!; \
	  trap 'kill $$SRV 2>/dev/null; rm -rf check_tmp' EXIT HUP INT TERM; \
	  for i in 1 2 3 4 5 6 7 8 9 10; do \
	    if ./volley -sf $(BASE)/version >/dev/null 2>&1; then break; fi; \
	    sleep 0.2; \
	  done; \
	  bad=0; \
	  echo "== CLI gates =="; \
	  ./volley -V | grep -q "volley 1.0.0" && echo "  ok   -V" || { echo "  FAIL -V"; bad=1; }; \
	  ./volley -h | grep -q -- "--http11" && echo "  ok   -h lists --http11" || { echo "  FAIL -h --http11"; bad=1; }; \
	  ./volley -h | grep -q -- "--client-cert" && echo "  ok   -h lists --client-cert" || { echo "  FAIL -h --client-cert"; bad=1; }; \
	  ./volley --http11 -sf $(BASE)/version | grep -q "volley_serve" && echo "  ok   --http11 fetch" || { echo "  FAIL --http11 fetch"; bad=1; }; \
	  ./volley --http2 -sf $(BASE)/version | grep -q "volley_serve" && echo "  ok   --http2 falls back to HTTP/1.1" || { echo "  FAIL --http2 fallback"; bad=1; }; \
	  ./volley -sf $(BASE)/version | grep -q "volley_serve on libvolley" && echo "  ok   /version route" || { echo "  FAIL /version route"; bad=1; }; \
	  ./volley -sf $(BASE)/b64/hello | grep -q "aGVsbG8=" && echo "  ok   /b64 route" || { echo "  FAIL /b64 route"; bad=1; }; \
	  ./volley -sf $(BASE)/gzip/hello | grep -q "content identical" && echo "  ok   /gzip route" || { echo "  FAIL /gzip route"; bad=1; }; \
	  if ./volley -sf -f $(BASE)/nope >/dev/null 2>&1; then echo "  FAIL -f should exit nonzero on 404"; bad=1; else echo "  ok   -f exits nonzero on 404"; fi; \
	  echo "== mTLS flag gates =="; \
	  if ./volley --client-cert /x.pem http://127.0.0.1:1/ >/dev/null 2>&1; then echo "  FAIL cert without key accepted"; bad=1; else echo "  ok   --client-cert requires --client-key"; fi; \
	  if ./volley --client-key /x.pem http://127.0.0.1:1/ >/dev/null 2>&1; then echo "  FAIL key without cert accepted"; bad=1; else echo "  ok   --client-key requires --client-cert"; fi; \
	  if ./volley --client-cert /nope.pem --client-key /nope.key http://127.0.0.1:1/ >/dev/null 2>&1; then echo "  FAIL bogus cert accepted"; bad=1; else echo "  ok   bogus cert rejected at engine start"; fi; \
	  echo "== library gates =="; \
	  ./smoke $(BASE)/version >/dev/null 2>&1 && echo "  ok   smoke.c links + fetches" || { echo "  FAIL smoke"; bad=1; }; \
	  ./check_api $(BASE) && echo "  ok   check_api (large_fetch + last_error)" || { echo "  FAIL check_api"; bad=1; }; \
	  echo "== session + chunked gates =="; \
	  HOME=check_tmp ./volley -S user1 -s $(BASE)/setcookie >/dev/null 2>&1; \
	  test -f "check_tmp/.config/volley/sessions/127.0.0.1:$(PORT)/user1.json" && echo "  ok   -S writes session json" || { echo "  FAIL -S session file"; bad=1; }; \
	  HOME=check_tmp ./volley -S user1 -sf $(BASE)/echo | grep -q "cookie=sid=abc123" && echo "  ok   -S cookie captured + resent" || { echo "  FAIL -S cookie persist"; bad=1; }; \
	  HOME=check_tmp ./volley -S user2 -H "X-Persist: hello" -sf $(BASE)/echo | grep -q "x-persist=hello" && echo "  ok   -S header stored" || { echo "  FAIL -S header stored"; bad=1; }; \
	  HOME=check_tmp ./volley -S user2 -sf $(BASE)/echo | grep -q "x-persist=hello" && echo "  ok   -S header persisted across runs" || { echo "  FAIL -S header persisted"; bad=1; }; \
	  head -c 300 /dev/zero | tr '\0' A > check_tmp/up.bin; \
	  ./volley --chunked -T check_tmp/up.bin -sf $(BASE)/echo | grep -q "transfer-encoding=chunked" && echo "  ok   --chunked sends TE: chunked" || { echo "  FAIL --chunked TE"; bad=1; }; \
	  ./volley --chunked -T check_tmp/up.bin -sf $(BASE)/echo | grep -q "decoded-body-bytes=300" && echo "  ok   --chunked body decoded (300B)" || { echo "  FAIL --chunked body bytes"; bad=1; }; \
	  echo "== git porcelain-lite gates (offline fixture) =="; \
	  rm -rf check_tmp/gitfix check_tmp/gitnew check_tmp/gitbare; \
	  MAIN=$$(./gittest check_tmp/gitfix); \
	  test "$$(./volley -C check_tmp/gitfix rev-parse main)" = "$$MAIN" && echo "  ok   -C option resolves rev" || { echo "  FAIL -C option"; bad=1; }; \
	  ./volley init check_tmp/gitnew | grep -q 'initialized empty repository' && test -f check_tmp/gitnew/.git/HEAD && echo "  ok   init creates repo" || { echo "  FAIL init"; bad=1; }; \
	  ./volley init --bare check_tmp/gitbare >/dev/null 2>&1 && test -f check_tmp/gitbare/config && grep -q 'bare = true' check_tmp/gitbare/config && echo "  ok   init --bare" || { echo "  FAIL init --bare"; bad=1; }; \
	  ./volley -C check_tmp/gitfix branch | grep -q '^\* main' && echo "  ok   branch marks current" || { echo "  FAIL branch current"; bad=1; }; \
  ./volley -C check_tmp/gitfix branch | grep -q '^  dev$$' && echo "  ok   branch lists others" || { echo "  FAIL branch dev"; bad=1; }; \
  ./volley -C check_tmp/gitfix tag | grep -qx 'v1.0.0' && echo "  ok   tag v1.0.0" || { echo "  FAIL tag v1.0.0"; bad=1; }; \
  ./volley -C check_tmp/gitfix tag | grep -qx 'v0.9.0' && echo "  ok   tag v0.9.0" || { echo "  FAIL tag v0.9.0"; bad=1; }; \
  ./volley -C check_tmp/gitfix remote | grep -qx 'origin' && echo "  ok   remote lists origin" || { echo "  FAIL remote"; bad=1; }; \
  ./volley -C check_tmp/gitfix remote -v | grep -q 'origin[[:space:]]*https://example.com/gitfix.git' && echo "  ok   remote -v shows url" || { echo "  FAIL remote -v"; bad=1; }; \
  ./volley -C check_tmp/gitfix remote add upstream https://example.com/upstream.git | grep -q 'added remote upstream' && ./volley -C check_tmp/gitfix remote | grep -qx 'upstream' && echo "  ok   remote add" || { echo "  FAIL remote add"; bad=1; }; \
  test "$$(./volley -C check_tmp/gitfix rev-parse main)" = "$$MAIN" && echo "  ok   rev-parse main" || { echo "  FAIL rev-parse main"; bad=1; }; \
  test "$$(./volley -C check_tmp/gitfix rev-parse HEAD)" = "$$MAIN" && echo "  ok   rev-parse HEAD" || { echo "  FAIL rev-parse HEAD"; bad=1; }; \
  test "$$(./volley -C check_tmp/gitfix rev-parse origin/main refs/tags/v0.9.0 | tail -n1)" = "$$MAIN" && echo "  ok   rev-parse multiple refs" || { echo "  FAIL rev-parse multiple"; bad=1; }; \
  test "$$(./volley -C check_tmp/gitfix cat-file -t $$MAIN)" = "commit" && echo "  ok   cat-file -t" || { echo "  FAIL cat-file -t"; bad=1; }; \
  ./volley -C check_tmp/gitfix cat-file -p $$MAIN | grep -q '^first commit' && echo "  ok   cat-file -p commit" || { echo "  FAIL cat-file -p commit"; bad=1; }; \
  ./volley -C check_tmp/gitfix ls-tree HEAD | grep -q '100644 blob' && echo "  ok   ls-tree HEAD" || { echo "  FAIL ls-tree"; bad=1; }; \
  ./volley -C check_tmp/gitfix ls-tree HEAD | grep -q 'hello.txt' && echo "  ok   ls-tree names" || { echo "  FAIL ls-tree names"; bad=1; }; \
  ./volley -C check_tmp/gitfix log | head -n1 | grep -q 'first commit' && echo "  ok   log subject" || { echo "  FAIL log subject"; bad=1; }; \
  ./volley -C check_tmp/gitfix log | grep -q "$$(echo $$MAIN | cut -c1-7)" && echo "  ok   log short oid" || { echo "  FAIL log short oid"; bad=1; }; \
  test $$bad -eq 0 && echo "== check passed ==" || { echo "== check failed =="; exit 1; }


chk_syntax:
	@$(CC) $(CFLAGS) -fsyntax-only -DVOLLEY_LIB $(SRCDIR)/volley.c
	@echo "  ok   -fsyntax-only -DVOLLEY_LIB"


# test: check, then best-effort online gates (network required).
test: check
	@echo "== online gates (network) =="
	@./volley --http11 -sf https://nghttp2.org/ | grep -q "HTTP/2 C Library" && echo "  ok   --http11 https://nghttp2.org" || { echo "  FAIL --http11 online"; exit 1; }
	@./volley --http2  -sf https://nghttp2.org/ | grep -q "HTTP/2 C Library" && echo "  ok   --http2  https://nghttp2.org" || { echo "  FAIL --http2 online"; exit 1; }
	@./volley ls-remote https://github.com/curl/curl.git | grep -q "refs/heads/" && echo "  ok   ls-remote github (curl)" || echo "  skip ls-remote github (unreachable)"
