/* libvolley.h - public API for the volley fetch engine.
 *
 * volley can be built as a small shared/static library so other programs
 * can fetch resources, parse URLs, encode, inflate and even clone a git
 * repository over HTTP -- without a shelling out to curl or git.
 *
 * Build: see the Makefile (make lib -> libvolley.a, libvolley.so).
 * Usage: link with -lvolley -lssl -lcrypto -lz -pthread.
 */
#ifndef LIBVOLLEY_H
#define LIBVOLLEY_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VOLLEY_VERSION_STRING "1.0.0"

/* ---------------------------------------------------------------- */
/* global setup / teardown                                           */
/* ---------------------------------------------------------------- */
void          volley_global_init(void);     /* TLS context, CA bundle, pool */
void          volley_global_cleanup(void);  /* release everything            */
const char   *volley_version(void);

/* ---------------------------------------------------------------- */
/* parsed URL                                                        */
/* ---------------------------------------------------------------- */
struct volley_url {
  char scheme[16];
  char host[256];
  char port[8];
  char path[2048];
  char auth[256];         /* user:pass from the URL, "" if none */
  int  https;
};

int volley_parse_url(const char *url, struct volley_url *out); /* 0 ok */
void volley_url_free(struct volley_url *u);                   /* no-op */

/* ---------------------------------------------------------------- */
/* one-shot fetch                                                    */
/* ---------------------------------------------------------------- */
struct volley_opts {
  const char *method;         /* default "GET"                      */
  const char *url;            /* required                           */
  const char *proxy;          /* http://h:p | https://h:p | socks5://h:p */
  const char *proxy_user;     /* user:pass for the proxy, optional  */
  const char *user;           /* basic-auth user:pass on the target? no: this
                                 is the URL userinfo / basic auth credentials */
  const char *body;           /* request body (POST/PUT)            */
  size_t      body_len;
  const char *range;          /* byte range, e.g. "0-1023"          */
  const char *useragent;      /* default "volley/1.0.0"             */
  const char *const *headers; /* NUL-terminated "Name: value" array or NULL */
  long        timeout_s;      /* 0 = none                           */
  int         insecure;       /* skip TLS verification              */
  int         follow;         /* follow redirects (default 1)       */
  int         max_redirs;     /* default 10                         */
  int         ipv;            /* 0 any, 4, 6                        */
  int         no_content_decode; /* pass raw (compressed) bytes     */
};

struct volley_result {
  int  status;                /* HTTP code; 0 on transport failure */
  int  ok;                    /* transport-level success flag      */
  long long bytes;            /* decoded body bytes                */
  long long total;            /* content-length / range total, -1  */
  double ms;
  char err[1024];             /* empty on success                  */
  char final_url[4096];       /* after redirects                   */
  unsigned char *body;        /* malloc'd decoded body (may be empty); 
                                 free with volley_result_free()     */
  size_t body_len;
};

/* Fetch one resource into r->body. Returns 0 on success (HTTP status
 * still in r->status), -1 on transport errors. On success the caller owns
 * r->body. */
int volley_fetch(const struct volley_opts *o, struct volley_result *r);
void volley_result_free(struct volley_result *r);

/* handy one-liners; err may be NULL */
int volley_get(const char *url, struct volley_result *r,
               char *err, size_t errsz);
int volley_head(const char *url, struct volley_result *r,
                char *err, size_t errsz);

/* ---------------------------------------------------------------- */
/* small helpers exposed for reuse                                   */
/* ---------------------------------------------------------------- */
int volley_b64_encode(const unsigned char *in, size_t inlen,
                      char *out, size_t outcap);            /* 0 ok */
int volley_b64_decode(const char *in, unsigned char *out,
                      size_t outcap, size_t *outlen);       /* 0 ok */
/* inflate gzip/zlib (auto-detected) data into a malloc'd buffer */
int volley_gzip_inflate(const unsigned char *in, size_t inlen,
                        unsigned char **out, size_t *outlen,
                        char *err, size_t errsz);           /* 0 ok */

/* ---------------------------------------------------------------- */
/* git clone WITHOUT git (smart HTTP transport)                      */
/* ---------------------------------------------------------------- */
struct volley_git_opts {
  int  verbose;
  int  quiet;
  int  bare;                  /* heads only, no working tree   */
};
/* Clone the repository at url (http/https, smart protocol) into destdir.
 * Returns 0 on success, -1 on failure (err filled). */
int volley_git_clone(const char *url, const char *destdir,
                     const struct volley_git_opts *o,
                     char *err, size_t errsz);

/* ---------------------------------------------------------------- */
/* last error + large downloads                                      */
/* ---------------------------------------------------------------- */
/* Thread-local error from the most recent failed volley_* transfer call in
 * the calling thread; NULL if the last call succeeded or never ran. Use from
 * the SAME thread that made the call. */
const char *volley_last_error(void);
void        volley_error_clear(void);

/* Stream url directly to path with O(1) memory: the body is written to disk
 * as it arrives, never buffered. Sends "Accept-Encoding: identity".
 * resume_at > 0 issues a "Range: bytes=<resume_at>-" and appends; a 206 is
 * validated against the requested point (Content-Range first-byte / total),
 * and if the server ignores the Range the download restarts from byte 0.
 * Returns 0 on transport-level success (r->status holds the HTTP code),
 * -1 on transport errors or an invalid Content-Range (r->err and
 * volley_last_error() describe the problem). r->body is never filled. */
int volley_large_fetch(const char *url, const char *path, long long resume_at,
                       struct volley_result *r);

#ifdef __cplusplus
}
#endif

#endif /* LIBVOLLEY_H */