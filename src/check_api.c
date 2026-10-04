/* check_api.c - link + runtime verification of the newer libvolley surface:
 *
 *   volley_large_fetch  -> /big/<n> streamed to a file, O(1) memory
 *   streaming           -> r->body must stay NULL (never buffered)
 *   volley_last_error   -> set after a failed connect, cleared on success
 *   volley_error_clear  -> resets the thread-local buffer
 *
 * Build/link by `make check`. Usage: check_api http://127.0.0.1:PORT
 */
#include "libvolley.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, msg) do { \
  if(cond) printf("       ok   %s\n", msg); \
  else     { printf("       FAIL %s\n", msg); failures++; } \
} while(0)

int main(int argc, char **argv)
{
  const char *base = argc > 1 ? argv[1] : "http://127.0.0.1:18085";
  char url[2048];

  volley_global_init();
  printf("       version = %s\n", volley_version());

  /* 1. volley_large_fetch: stream /big/8388608 to a file. */
  {
    struct volley_result r;
    const char *path = "check_tmp/big.bin";
    snprintf(url, sizeof url, "%s/big/8388608", base);
    memset(&r, 0, sizeof r);
    int rc = volley_large_fetch(url, path, 0, &r);
    CHECK(rc == 0, "large_fetch returned 0");
    CHECK(r.status == 200, "large_fetch HTTP 200");
    CHECK(r.ok == 1, "large_fetch net ok");
    CHECK(r.total == 8388608, "large_fetch total == 8388608");
    CHECK(r.bytes == 8388608, "large_fetch bytes == 8388608");
    CHECK(r.body == NULL && r.body_len == 0,
          "large_fetch streamed (body never buffered)");
    {
      FILE *f = fopen(path, "rb");
      if(!f) {
        CHECK(0, "large_fetch file exists");
      } else {
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        unsigned char b0 = 0, b1 = 0, b4095 = 0, b4096 = 0;
        if(sz >= 4097) {
          fseek(f, 4096, SEEK_SET);
          if(fread(&b4096, 1, 1, f) != 1) b4096 = 0;
          fseek(f, 4095, SEEK_SET);
          if(fread(&b4095, 1, 1, f) != 1) b4095 = 0;
          fseek(f, 1, SEEK_SET);
          if(fread(&b1, 1, 1, f) != 1) b1 = 0;
          fseek(f, 0, SEEK_SET);
          if(fread(&b0, 1, 1, f) != 1) b0 = 0;
        }
        fclose(f);
        CHECK(sz == 8388608, "large_fetch file size == 8388608");
        CHECK(b0 == (unsigned char)((0LL) * 31 + 7), "large_fetch byte@0 == 7");
        CHECK(b1 == (unsigned char)((1LL) * 31 + 7), "large_fetch byte@1 == 38");
        CHECK(b4095 == (unsigned char)((4095LL) * 31 + 7), "large_fetch byte@4095");
        CHECK(b4096 == (unsigned char)((4096LL) * 31 + 7), "large_fetch byte@4096");
        remove(path);
      }
    }
    volley_result_free(&r);
  }

  /* 2. volley_last_error: a connect-refused transfer must record it. */
  {
    struct volley_opts o;
    struct volley_result r;
    memset(&o, 0, sizeof o);
    o.url = "http://127.0.0.1:1/nothing-listens-here";
    memset(&r, 0, sizeof r);
    int rc = volley_fetch(&o, &r);
    CHECK(rc != 0, "connect-refused fetch fails");
    const char *le = volley_last_error();
    CHECK(le != NULL && le[0], "volley_last_error set after failure");
    if(le && le[0]) printf("       last error: %s\n", le);
    volley_result_free(&r);
  }

  /* 3. success must clear the last error; volley_error_clear -> NULL. */
  {
    struct volley_opts o;
    struct volley_result r;
    snprintf(url, sizeof url, "%s/version", base);
    memset(&o, 0, sizeof o);
    o.url = url;
    memset(&r, 0, sizeof r);
    int rc = volley_fetch(&o, &r);
    CHECK(rc == 0, "version fetch ok");
    CHECK(r.status == 200, "version fetch HTTP 200");
    CHECK(r.err[0] == 0, "version fetch res.err empty");
    CHECK(r.body && strstr((const char *)r.body, "volley_serve") != NULL,
          "version body mentions volley_serve");
    volley_result_free(&r);
    CHECK(volley_last_error() == NULL || !volley_last_error()[0],
          "volley_last_error empty after success");
    volley_error_clear();
    CHECK(volley_last_error() == NULL, "volley_error_clear resets to NULL");
  }

  volley_global_cleanup();
  if(failures) {
    fprintf(stderr, "check_api: %d failure(s)\n", failures);
    return 1;
  }
  printf("       check_api: all checks passed\n");
  return 0;
}