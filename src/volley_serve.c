/* volley_serve.c — example HTTP server linked against libvolley.so
 *
 * This is a *consumer* example, the reverse direction to smoke.c: an actual
 * long-running server whose binary links -lvolley and calls five of its
 * exported helpers (version / parse_url / b64 / gzip / one volley_get). It
 * proves the shared library is usable from a standalone, non-CLI process —
 * i.e. libvolley.so links "both ways":
 *
 *   volley CLI       -> libvolley  (the browser/CLI we already have)
 *   volley_serve     -> libvolley  (this file: a server, not the CLI)
 *
 * Build:
 *   cc -O2 -pthread -o volley_serve volley_serve.c \
 *      -L. -lvolley -lssl -lcrypto -lz -Wl,-rpath,$PWD
 *   ./volley_serve 8080
 *   then:  volley http://127.0.0.1:8080/version           -> "volley 1.0.0"
 *          curl  http://127.0.0.1:8080/b64/hello           -> aGVsbG8=
 *
 * It is deliberately tiny and single-threaded: one listener, accept(), read a
 * request, serve a small text route, close. Enough to prove linkability and
 * the .so contract; not a production server.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <zlib.h>

#include "libvolley.h"

#define REQ_MAX 8192
#define BODY_MAX 65536

/* find a request header value (case-insensitive name, one space after ':') */
static void srchdr(const char *req, const char *name, char *out, size_t n);
static int req_complete(const char *req, size_t len) {
  const char *hd = strstr(req, "\r\n\r\n");
  char te[64], cl[64];
  (void)len;
  if (!hd) return 0;
  srchdr(req, "Transfer-Encoding:", te, sizeof te);
  srchdr(req, "Content-Length:", cl, sizeof cl);
  if (strstr(te, "chunked"))
    return strstr(req, "\r\n0\r\n\r\n") != NULL;
  if (cl[0])
    return (size_t)(hd - req) + 4 + (size_t)atoll(cl) <= strlen(req);
  return 1;
}

static void http_reply(int fd, int code, const char *ctype,
                       const char *body, size_t blen) {
  char hdr[512];
  int n = snprintf(hdr, sizeof hdr,
                   "HTTP/1.1 %d OK\r\n"
                   "Content-Type: %s\r\n"
                   "Content-Length: %zu\r\n"
                   "Server: volley_serve %s\r\n"
                   "Connection: close\r\n\r\n",
                   code, ctype, blen, volley_version());
  (void)!write(fd, hdr, (size_t)n);
  if (body && blen) (void)!write(fd, body, blen);
}

/* find a request header value (case-insensitive name, one space after ':') */
static void srchdr(const char *req, const char *name, char *out, size_t n) {
  const char *head_end = strstr(req, "\r\n\r\n");
  size_t in_headers = head_end ? (size_t)(head_end - req) : strlen(req);
  const char *p = req, *found = NULL;
  out[0] = 0;
  while ((p = strstr(p, name)) != NULL) {
    if ((size_t)(p - req) < in_headers &&
        (p == req || p[-1] == '\n')) { found = p; break; }
    p += strlen(name);
  }
  if (!found) return;
  const char *v = found + strlen(name);
  while (*v == ' ' || *v == '\t') v++;
  size_t k = 0;
  while (v[k] && v[k] != '\r' && v[k] != '\n' && k + 1 < n) k++;
  memcpy(out, v, k); out[k] = 0;
}

/* decode a chunked body (raw bytes after the header block). Returns bytes
   decoded, -1 on malformed input. */
static long long chunked_decode(const char *p, size_t len, char *out,
                                size_t outsz) {
  size_t op = 0, off = 0;
  while (op + 1 < outsz && off < len) {
    long long sz = 0; int digits = 0;
    while (off < len && isxdigit((unsigned char)p[off])) {
      int d = p[off];
      sz = sz * 16 + (d <= '9' ? d - '0' : (d <= 'F' ? d - 'A' + 10 : d - 'a' + 10));
      off++; digits++;
    }
    (void)digits;
    while (off < len && (p[off] == '\r' || p[off] == '\n')) off++;
    if (sz == 0) return (long long)op;   /* end marker 0\r\n\r\n */
    if (sz < 0 || (size_t)sz > len - off) sz = (long long)(len - off);
    if ((size_t)sz > outsz - op - 1) sz = (long long)(outsz - op - 1);
    memcpy(out + op, p + off, (size_t)sz);
    op += (size_t)sz; off += (size_t)sz;
    while (off < len && (p[off] == '\r' || p[off] == '\n')) off++;
  }
  return (long long)op;
}

int main(int argc, char **argv) {
  int port = (argc > 1) ? atoi(argv[1]) : 8080;

  /* 1. Every exported symbol we touch is a compile-time .so link.
   *    volley_version() is the cheapest proof the lib loaded. */
  printf("volley_serve starting on :%d (lib = %s)\n", port, volley_version());

  int ls = socket(AF_INET, SOCK_STREAM, 0);
  if (ls < 0) { perror("socket"); return 1; }
  int one = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

  struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
  sa.sin_family      = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_ANY);
  sa.sin_port        = htons((uint16_t)port);
  if (bind(ls, (struct sockaddr *)&sa, sizeof sa) < 0) { perror("bind"); return 1; }
  if (listen(ls, 8) < 0) { perror("listen"); return 1; }

  for (;;) {
    int fd = accept(ls, NULL, NULL);
    if (fd < 0) continue;

    char req[REQ_MAX + 1]; memset(req, 0, sizeof req);
    ssize_t rl = read(fd, req, REQ_MAX);
    if (rl <= 0) { close(fd); continue; }
    /* Keep reading until the request looks complete (headers + body) or the
     * buffer is full, so we never reply while the client is still sending. */
    while (rl < (ssize_t)REQ_MAX && !req_complete(req, (size_t)rl)) {
      ssize_t r2 = read(fd, req + rl, (size_t)(REQ_MAX - rl));
      if (r2 <= 0) break;
      rl += r2;
      req[(rl < REQ_MAX) ? (size_t)rl : REQ_MAX] = 0;
    }
    req[(rl < REQ_MAX) ? (size_t)rl : REQ_MAX] = 0;

    /* GET <path> HTTP/1.x  (parse a copy; keep req intact for header lookups) */
    char *line = strchr(req, '\n');
    if (!line) { close(fd); continue; }
    char reqline[1200];
    size_t firstlen = (size_t)(line - req);
    if (firstlen > sizeof reqline - 1) firstlen = sizeof reqline - 1;
    memcpy(reqline, req, firstlen); reqline[firstlen] = 0;
    char method[16] = {0}, pth[1024] = {0}, proto[16] = {0};
    if (sscanf(reqline, "%15s %1023s %15s", method, pth, proto) != 3) { close(fd); continue; }
    (void)proto;

    /* 2. volley_parse_url: reuse the library's URL splitter on pth. */
    struct volley_url u; memset(&u, 0, sizeof u);
    char urlbuf[1200]; snprintf(urlbuf, sizeof urlbuf, "http://%s%s", "mock", pth);
    (void)volley_parse_url(urlbuf, &u);

    char body[BODY_MAX]; body[0] = 0;

    if (strncmp(pth, "/big/", 5) == 0) {
      /* Streaming route: /big/<n> returns exactly n deterministic bytes with
       * a correct Content-Length, exercising large_fetch / -o.- streaming. */
      long long want = atoll(pth + 5);
      if (want < 0) want = 0;
      char bighdr[256];
      int bn = snprintf(bighdr, sizeof bighdr,
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: application/octet-stream\r\n"
                        "Content-Length: %lld\r\n"
                        "Server: volley_serve %s\r\n"
                        "Connection: close\r\n\r\n",
                        want, volley_version());
      (void)!write(fd, bighdr, (size_t)bn);
      char chunk[4096];
      for (long long off = 0; off < want; ) {
        size_t take = (want - off > (long long)sizeof chunk)
                      ? sizeof chunk : (size_t)(want - off);
        for (size_t i = 0; i < take; i++)
          chunk[i] = (char)((off + (long long)i) * 31 + 7);
        (void)!write(fd, chunk, take);
        off += (long long)take;
      }
      close(fd);
      continue;
    }

    if (strncmp(pth, "/setcookie", 10) == 0) {
      /* Sets a cookie: /setcookie[/<value>]. Test bed for sessions. */
      const char *val = (pth[10] == '/') ? pth + 11 : "abc123";
      char out[512];
      int n = snprintf(out, sizeof out,
                       "HTTP/1.1 200 OK\r\n"
                       "Set-Cookie: sid=%s; Path=/; HttpOnly\r\n"
                       "Content-Length: 11\r\n"
                       "Connection: close\r\n\r\n"
                       "cookie set!", val);
      (void)!write(fd, out, (size_t)n);
      close(fd);
      continue;
    }

    if (strcmp(pth, "/echo") == 0) {
      /* Echo back key request headers and, for chunked bodies, the number of
       * decoded body bytes. Test bed for sessions and --chunked. */
      char ua[512] = "", ckb[1024] = "", te[128] = "", xp[512] = "";
      char cl[128] = "", clen2[128] = "";
      srchdr(req, "User-Agent:", ua, sizeof ua);
      srchdr(req, "Cookie:", ckb, sizeof ckb);
      srchdr(req, "Transfer-Encoding:", te, sizeof te);
      srchdr(req, "X-Persist:", xp, sizeof xp);
      srchdr(req, "Content-Length:", cl, sizeof cl);
      (void)clen2;
      snprintf(body, sizeof body,
               "transfer-encoding=%s\ncontent-length=%s\ncookie=%s\n"
               "user-agent=%s\nx-persist=%s\n",
               te[0] ? te : "none", cl[0] ? cl : "none", ckb[0] ? ckb : "none",
               ua[0] ? ua : "none", xp[0] ? xp : "none");
      if (strstr(te, "chunked")) {
        const char *after = strstr(req, "\r\n\r\n");
        char dec[BODY_MAX];
        long long n = 0;
        if (after) {
          const char *bstart = after + 4;
          size_t blen = (size_t)(rl) - (size_t)(bstart - req);
          n = chunked_decode(bstart, blen, dec, sizeof dec);
        }
        char extra[128];
        snprintf(extra, sizeof extra, "decoded-body-bytes=%lld\n", n);
        strncat(body, extra, sizeof body - strlen(body) - 1);
      }
      http_reply(fd, 200, "text/plain", body, strlen(body));
      close(fd);
      continue;
    }

    if (strcmp(pth, "/") == 0 || strcmp(pth, "/version") == 0) {
      /* 3. plain text route, populated with the .so's version string. */
      snprintf(body, sizeof body,
               "volley_serve on libvolley (%s)\r\n"
               "parsed path via volley_parse_url: scheme=%s host=%s port=%s path=%s\r\n",
               volley_version(), u.scheme[0] ? u.scheme : "?", u.host,
               u.port[0] ? u.port : "?", u.path);
      http_reply(fd, 200, "text/plain", body, strlen(body));
    } else if (strncmp(pth, "/b64/", 5) == 0) {
      /* 4. volley_b64_encode: echo base64 of the payload after /b64/. */
      const char *payload = pth + 5;
      size_t plen = strlen(payload);
      char *b64 = malloc(plen * 4 + 16);
      if (b64) {
        volley_b64_encode((const unsigned char *)payload, plen, b64, plen * 4 + 16);
        http_reply(fd, 200, "text/plain", b64, strlen(b64));
        free(b64);
      } else http_reply(fd, 500, "text/plain", "oom", 3);
    } else if (strncmp(pth, "/gzip/", 6) == 0) {
      /* 5. volley_gzip_inflate: take zlib-compressed bytes we produce with
       *    the lib's own zlib (compress2) and round-trip via the exported
       *    inflate helper — proving the .so contract end-to-end. */
      const char *payload = pth + 6;
      unsigned long clen = BODY_MAX;
      unsigned char *cz = malloc((size_t)clen);
      if (cz && compress2(cz, &clen,
                          (const unsigned char *)payload, (uLong)strlen(payload),
                          6) == Z_OK) {
        unsigned char *back = NULL; size_t blen2 = 0;
        char err[256];
        if (volley_gzip_inflate(cz, (size_t)clen, &back, &blen2, err, sizeof err) == 0) {
          snprintf(body, sizeof body,
                   "gzip round-trip ok: %zu -> %lu -> %zu inflate back\r\n",
                   strlen(payload), clen, blen2);
          if (blen2 == strlen(payload) && !memcmp(back, payload, blen2))
            strcat(body, "content identical\r\n");
          else strcat(body, "CONTENT MISMATCH\r\n");
          free(back);
        } else snprintf(body, sizeof body, "inflate err: %s\r\n", err);
      } else snprintf(body, sizeof body, "compress err\r\n");
      free(cz); cz = NULL;
      http_reply(fd, 200, "text/plain", body, strlen(body));
    } else {
      snprintf(body, sizeof body, "unknown route %s\r\n", pth);
      http_reply(fd, 404, "text/plain", body, strlen(body));
    }

    close(fd);
  }
  close(ls);
  return 0;
}