/***********************************************************************
 *              _            _
 *    __      _| | __ _  ___| |_
 *  / /\ \ / /| |/ _` |/ __| __|
 * | |  \ V / | | (_| | (__| |_
 * |_|   \_/  |_|\__,_|\___|\__| - Fetch your URLs. Faster.
 *
 * NAME
 *   volley
 *
 * DESCRIPTION
 *   Fetch HTTP/HTTPS resources. Faster and friendlier than the old ways:
 *   parallel multi-URL fetching, keep-alive connection reuse, segmented
 *   (parallel byte-range) downloads, chunked decoding, TLS with hostname
 *   verification, colored output and a live progress meter.
 *
 * COMPILATION
 *   Compile with:  make            (builds ./volley plus ./libvolley.a/.so)
 *   Or manually:   cc -O2 -Wall -pthread volley.c -o volley -lssl -lcrypto -lz
 *
 * USAGE
 *   (invoke without argument to get the help text)
 *
 *   Example: volley https://asgfr.vercel.app/
 *            volley -j 8 https://one.example/a.bin https://two.example/b.bin
 *            volley -c 4 -o big.bin https://cdn.example/big.iso
 *            volley clone https://github.com/user/repo.git repo/
 *
 * BIBLIOGRAPHY
 *   - RFC 7230/7231: HTTP/1.1 message syntax and semantics
 *   - RFC 7233:      Range requests / partial content
 *   - RFC 1928/1929: SOCKS5 protocol and username/password auth
 *   - RFC 1952/1950: gzip / zlib data formats (content decoding)
 *   - "HTTP - The Definitive Guide" - David Gourley and Brian Totty
 *   - gitformat-pack(5), gitprotocol-http(5): pack format, smart HTTP
 *
 * TODO:
 *   - (Protocol) HTTP/2 via nghttp2, HTTP/3 via quic
 *   - (Protocol) FTP/GOPHER support for completeness
 *   - (Feature)  gzip on the wire is handled; add brotli/zstd
 *   - (Feature)  git clone: add depth/shallow, tags, submodules
 *   - (Feature)  SOCKS4 and HTTP/2 proxy support
 *
 * SPIRITUAL HERITAGE
 *   Inspired by "urlget.c" by Rafael Sagula / Daniel Stenberg --
 *   the tool that grew up to become curl.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define VOLLEY_VERSION "1.0.0"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <getopt.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <zlib.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include <openssl/pem.h>

#include "libvolley.h"

/* ---------------------------------------------------------------- */
/* limits                                                            */
/* ---------------------------------------------------------------- */
#define VOLLEY_MAX_HDRS   64
#define VOLLEY_MAX_POOL   16
#define VOLLEY_MAX_REDIRS 10
#define VOLLEY_MAX_SEGS   64
#define VOLLEY_MAX_URLS   256
#define VOLLEY_LINE       8192
#define VOLLEY_IO         65536

/* ---------------------------------------------------------------- */
/* small utility helpers                                             */
/* ---------------------------------------------------------------- */
static double now_ms(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

static void fmt_size(long long n, char *out)
{
  if(n < 1024)
    snprintf(out, 16, "%lldB", n);
  else if(n < 1024LL*1024)
    snprintf(out, 16, "%.1fK", n/1024.0);
  else if(n < 1024LL*1024*1024)
    snprintf(out, 16, "%.1fM", n/(1024.0*1024));
  else if(n < 1024LL*1024*1024*1024)
    snprintf(out, 16, "%.1fG", n/(1024.0*1024*1024));
  else
    snprintf(out, 16, "%.1fT", n/(1024.0*1024*1024*1024));
}

/* ---- Base64 encoding (for Basic auth), in the urlget tradition ---- */
static const char table64[]=
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void base64_encode(const unsigned char *in, size_t inlen, char *out)
{
  unsigned char ibuf[3], obuf[4];
  size_t i, oi = 0;
  for(i = 0; i < inlen; i += 3) {
    int rem = (int)(inlen - i);
    int j;
    for(j = 0; j < 3; j++)
      ibuf[j] = (rem > j) ? in[i+(size_t)j] : 0;
    obuf[0] =  (ibuf[0] & 0xFC) >> 2;
    obuf[1] = ((ibuf[0] & 0x03) << 4) | ((ibuf[1] & 0xF0) >> 4);
    obuf[2] = ((ibuf[1] & 0x0F) << 2) | ((ibuf[2] & 0xC0) >> 6);
    obuf[3] =  ibuf[2] & 0x3F;
    switch(rem) {
    case 1:
      snprintf(out+oi, 5, "%c%c==", table64[obuf[0]], table64[obuf[1]]);
      oi += 4;
      break;
    case 2:
      snprintf(out+oi, 5, "%c%c%c=", table64[obuf[0]], table64[obuf[1]],
               table64[obuf[2]]);
      oi += 4;
      break;
    default:
      snprintf(out+oi, 5, "%c%c%c%c", table64[obuf[0]], table64[obuf[1]],
               table64[obuf[2]], table64[obuf[3]]);
      oi += 4;
      break;
    }
  }
  out[oi] = 0;
}

/* ---------------------------------------------------------------- */
/* color magic                                                       */
/* ---------------------------------------------------------------- */
static int g_color = 0;               /* 0 off, 1 on */
static const char *CK = "";           /* color: reset */
static const char *CD = "";           /* color: dim */

static const char *status_color(int code)
{
  if(!g_color)
    return "";
  if(code == 0)  return "\033[35m";
  if(code < 200) return "\033[36m";
  if(code < 300) return "\033[32m";
  if(code < 400) return "\033[34m";
  if(code < 500) return "\033[33m";
  return "\033[31m";
}

static void set_color(int mode)
{
  g_color = (mode == 2) ? 1 : (mode == 1 ? (isatty(2) ? 1 : 0) : 0);
  CK = g_color ? "\033[0m" : "";
  CD = g_color ? "\033[2m" : "";
}

/* ---------------------------------------------------------------- */
/* parsed URL                                                        */
/* ---------------------------------------------------------------- */
typedef struct {
  char scheme[16];
  char host[256];
  char port[8];
  char path[2048];
  char auth[256];   /* user:pass found in the URL, "" if none */
  int https;
  int proto;        /* 0 = http(s), 1 = ftp, 2 = gopher */
} Url;

static int parse_url(const char *url, Url *p)
{
  char hb[1024] = {0};
  const char *rest;

  memset(p, 0, sizeof *p);

  rest = strstr(url, "://");
  if(!rest) {
    strcpy(p->scheme, "http");
    rest = url;
  }
  else {
    size_t n = (size_t)(rest - url);
    if(n > 15) n = 15;
    memcpy(p->scheme, url, n);
    p->scheme[n] = 0;
    for(char *c = p->scheme; *c; c++)
      *c = (char)tolower((unsigned char)*c);
    if(!strcmp(p->scheme, "ftp"))
      p->proto = 1;
    else if(!strcmp(p->scheme, "gopher"))
      p->proto = 2;
    else if(strcmp(p->scheme, "http") && strcmp(p->scheme, "https"))
      return -1;
    rest += 3;
  }
  p->https = !strcmp(p->scheme, "https");

  {
    const char *slash = strchr(rest, '/');
    if(slash) {
      size_t hl = (size_t)(slash - rest);
      if(hl >= sizeof hb) hl = sizeof hb - 1;
      memcpy(hb, rest, hl);
      hb[hl] = 0;
      snprintf(p->path, sizeof p->path, "%s", slash);
    }
    else {
      snprintf(hb, sizeof hb, "%s", rest);
      strcpy(p->path, "/");
    }
  }
  if(!hb[0])
    return -1;

  /* userinfo, like ftp://user:pass@host/ ... only http/https here */
  {
    char *at = strchr(hb, '@');
    if(at) {
      size_t ul = (size_t)(at - hb);
      if(ul >= sizeof p->auth) ul = sizeof p->auth - 1;
      memcpy(p->auth, hb, ul);
      p->auth[ul] = 0;
      memmove(hb, at + 1, strlen(at + 1) + 1);
    }
  }

  /* host and port, IPv6 aware */
  if(hb[0] == '[') {
    char *end = strchr(hb, ']');
    if(!end)
      return -1;
    {
      size_t hl = (size_t)(end - (hb + 1));
      memcpy(p->host, hb + 1, hl);
      p->host[hl] = 0;
    }
    if(end[1] == ':')
      snprintf(p->port, sizeof p->port, "%s", end + 2);
    else
      snprintf(p->port, sizeof p->port, "%s",
               p->proto == 2 ? "70" : p->proto == 1 ? "21" :
               p->https ? "443" : "80");
  }
  else {
    char *colon = strrchr(hb, ':');
    if(colon) {
      *colon = 0;
      snprintf(p->host, sizeof p->host, "%s", hb);
      snprintf(p->port, sizeof p->port, "%s", colon + 1);
    }
    else {
      snprintf(p->host, sizeof p->host, "%s", hb);
      snprintf(p->port, sizeof p->port, "%s",
               p->proto == 2 ? "70" : p->proto == 1 ? "21" :
               p->https ? "443" : "80");
    }
  }
  if(!p->host[0] || !p->port[0])
    return -1;
  return 0;
}

/* resolve a possibly-relative Location header against the current URL */
static void resolve_url(const char *cur, const char *loc, char *out, size_t cap)
{
  Url p;
  char hp[512];

  if(strstr(loc, "://")) {
    snprintf(out, cap, "%s", loc);
    return;
  }
  if(!strncmp(loc, "//", 2)) {
    if(parse_url(cur, &p))
      return;
    snprintf(out, cap, "%s:%s", p.scheme, loc);
    return;
  }
  if(parse_url(cur, &p))
    return;

  if(!strcmp(p.port, "443") && p.https)
    snprintf(hp, sizeof hp, "%s", p.host);
  else if(!strcmp(p.port, "80") && !p.https)
    snprintf(hp, sizeof hp, "%s", p.host);
  else
    snprintf(hp, sizeof hp, "%s:%s", p.host, p.port);

  if(loc[0] == '/') {
    snprintf(out, cap, "%s://%s%s", p.scheme, hp, loc);
    return;
  }
  if(loc[0] == '#') {
    snprintf(out, cap, "%s", cur);
    return;
  }
  /* relative path: keep the directory part of the current path */
  {
    const char *sl = strrchr(p.path, '/');
    char base[2048];
    if(sl) {
      size_t n = (size_t)(sl - p.path) + 1;
      memcpy(base, p.path, n);
      base[n] = 0;
    }
    else
      strcpy(base, "/");
    snprintf(out, cap, "%s://%s%s%s", p.scheme, hp, base, loc);
  }
}

/* ---------------------------------------------------------------- */
/* connection + TLS layer                                            */
/* ---------------------------------------------------------------- */
static long g_timeout = 0;   /* seconds, 0 = none (read/write idle) */
static long g_conn_timeout = 0; /* seconds, 0 = none (connect) */
static int  g_verbose = 0;
static int  g_af = 0;        /* 0 any, 4 = ipv4 only, 6 = ipv6 only */
static SSL_CTX *g_ctx = NULL;

/* retries + rate limiting */
static int  g_retries = 0;
static long g_retry_wait = 1;     /* seconds between attempts */
static int  g_retry_all = 0;
static long long g_limit_rate = 0; /* bytes per second, 0 = off */
static long long g_rate_start = -1; /* monotonic start of a rate window */
static long long g_rate_bytes = 0;

/* progress meter style: 0 = bar, 1 = dot */
static int  g_progstyle = 0;
static int  g_dot_bytes = 1024;
static int  g_dot_spacing = 10;
static int  g_dots_in_line = 50;
static int  g_screen_w = 80;

/* misc CLI state shared with the worker */
static int  g_listonly = 0;      /* -l/--list-only */
static int  g_upload_file = 0;   /* -T upload active */

/* config file + recursion settings */
static const char *g_conf_ua = NULL;       /* default UA from config */
static int  g_recursive = 0;               /* --recursive / mirror */
static int  g_level = 0;                   /* recursion depth, 0 = infinite */
static int  g_span_hosts = 0;
static int  g_mirror = 0;
static char g_domains[2048] = "";
static char g_accept[4096] = "";
static char g_reject[4096] = "";
static char g_dprefix[2048] = ".";
static char *g_conf_hdrs[64];
static int  g_nconfh = 0;
static int  g_http2 = 0;
static int  g_alpn_h2 = 0;      /* offer h2 over ALPN on https handshakes */
static char g_certfile[1024] = ""; /* --client-cert (PEM) for mTLS */
static char g_keyfile[1024] = "";  /* --client-key (PEM) for mTLS */
static int  g_netrc = 0;
static char g_netrc_file[1024] = "";
static __thread char g_lasterr[1024] = {0}; /* per-thread last error */
static int  g_mirror_active = 0;   /* suppresses normal stdout/summary */

/* -S/--session (httpie-style persistent per-host session) */
static char   g_session[1024] = "";  /* session name or anonymous path */
static int    g_sess_active = 0;     /* a session is bound */
static char   g_sess_host[256] = ""; /* host[:port] the session is bound to */
static char   g_sess_path[2048] = "";/* resolved JSON session file */
static char  *g_sess_hdrs[64];       /* persistent request headers */
static int    g_nsessh = 0;

/* --chunked streaming upload (Transfer-Encoding: chunked) */
static int    g_chunked = 0;
static FILE  *g_up_file = NULL;      /* open upload source when chunked */

/* proxy policy (global, configured before jobs start) */
typedef struct {
  int  type;       /* 0 none, 1 http/https proxy, 2 socks5 */
  int  s5h;        /* socks5h: let the proxy resolve names */
  char host[256];
  char port[8];
  char auth[512];  /* optional user:pass */
} Proxy;

static Proxy g_proxy;

static void rate_init(void);
static void rate_pace(long long bytes);

/* ---------------------------------------------------------------- */
/* rate limiting                                                     */
/* ---------------------------------------------------------------- */
static long long rate_mono_ms(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static void rate_init(void)
{
  g_rate_start = rate_mono_ms();
  g_rate_bytes = 0;
}
static void rate_pace(long long bytes)
{
  long long want, el, sleepms;
  struct timespec t;
  if(g_limit_rate <= 0)
    return;
  if(g_rate_start < 0)
    rate_init();
  g_rate_bytes += bytes;
  el = rate_mono_ms() - g_rate_start;
  want = (g_rate_bytes * 1000) / g_limit_rate;
  if(want <= el)
    return;
  sleepms = want - el;
  if(sleepms > 60000)
    sleepms = 60000;
  t.tv_sec = (time_t)(sleepms / 1000);
  t.tv_nsec = (sleepms % 1000) * 1000000L;
  nanosleep(&t, NULL);
  g_rate_bytes = (long long)(g_limit_rate * (double)(el + sleepms) / 1000.0);
  g_rate_start = rate_mono_ms();
}

/* ---------------------------------------------------------------- */
/* cookies                                                           */
/* ---------------------------------------------------------------- */
#define MAX_COOKIES 512
typedef struct {
  char domain[256];
  char path[512];
  char name[256];
  char value[1024];
  long long expiry;    /* 0 = session cookie */
  int secure;
  int alive;
} Cookie;

static Cookie  g_jar[MAX_COOKIES];
static int     g_ncookies = 0;
static int     g_cook_use = 0;    /* -b/--cookie given */
static int     g_cook_save = 0;   /* -c/--cookie-jar given */
static int     g_sess_only = 0;   /* -j/--junk-session-cookies */
static char    g_cook_file[2048];
static char    g_cook_in[4096];   /* literal "name=value; ..." from -b */
static int     g_cook_enabled = 1;

static long long cookie_now(void) { return (long long)time(NULL); }

/* RFC 6265 cookie-domain match: cookie domain applies to host */
static int cookie_domain_match(const char *cd, const char *host)
{
  size_t dl, hl;
  if(!cd[0])
    return 0;
  dl = strlen(cd);
  hl = strlen(host);
  if(!strcasecmp(cd, host))
    return 1;
  if(hl > dl && !strncasecmp(host + hl - dl, cd, dl) && host[hl - dl - 1] == '.')
    return 1;
  return 0;
}

/* RFC 6265 path-match */
static int cookie_path_match(const char *cp, const char *path)
{
  size_t cl = strlen(cp), pl = strlen(path);
  if(cl && path[0] != '/')
    return !cl;
  if(pl < cl)
    return 0;
  if(strncmp(path, cp, cl) != 0)
    return 0;
  if(cl == 1 && cp[0] == '/')
    return 1;
  if(pl == cl || path[cl] == '/')
    return 1;
  return 0;
}

static int cookie_parse_int(const char *s)
{
  int v = 0;
  while(*s && *s >= '0' && *s <= '9') { v = v * 10 + (*s - '0'); s++; }
  return v;
}

/* parse a date like "
<day>, DD-Mon-YYYY HH:MM:SS GMT" (RFC 850/cookie asctime tolerated) */
static long long cookie_parse_date(const char *s)
{
  static const char *mon[] = {"jan","feb","mar","apr","may","jun",
                              "jul","aug","sep","oct","nov","dec"};
  int day = -1, mo = -1, yr = -1, hh = -1, mi = -1, ss = -1;
  char t[64], *p, *tok, *save = NULL;
  int pass;
  snprintf(t, sizeof t, "%s", s);
  for(pass = 0; pass < 3; pass++) {
    p = t;
    while(*p) {
      char *w;
      if(isspace((unsigned char)*p)) { p++; continue; }
      w = p;
      while(*p && !isspace((unsigned char)*p) &&
            *p != ',' && *p != '-') p++;
      if(*p) { *p = 0; p++; }
      tok = w;
      if(!*tok || *tok == ':') { tok++; /* may point past p's '\0' - guard */ continue; }
      if(day < 0 && !strchr(tok, ':') &&
         tok[0] >= '0' && tok[0] <= '9') {
        int n = cookie_parse_int(tok);
        if(n >= 1 && n <= 31 && mo < 0) day = n;
      }
      else if(mo < 0) {
        for(int i = 0; i < 12; i++)
          if(strncasecmp(tok, mon[i], 3) == 0) { mo = i + 1; break; }
      }
    }
    break;
  }
  (void)save; (void)tok;
  /* extract digits: DD, YYYY, and times via strtok on ':' */
  {
    int nums[8] = {0}, n = 0;
    char c[64];
    snprintf(c, sizeof c, "%s", s);
    for(char *q = c; *q;) {
      if((*q >= '0' && *q <= '9') || *q == ':' || *q == ' ') q++;
      else q++;
    }
    for(int i = 0; i <= (int)strlen(c); i++) {
      if(i < (int)strlen(c) && c[i] >= '0' && c[i] <= '9') {
        tok = c + i;
        while(i < (int)strlen(c) && c[i] >= '0' && c[i] <= '9') i++;
        nums[n++] = cookie_parse_int(tok);
        if(n == 8) break;
      }
    }
    if(day < 0) day = nums[0];
    if(nums[n-2] >= 1970 && nums[n-2] < 2100) yr = nums[n-2];
    else if(nums[n-1] >= 1970 && nums[n-1] < 2100) yr = nums[n-1];
    for(int i = 0; i < n; i++)
      if(nums[i] <= 23 && i < n - 2) { hh = nums[i]; mi = nums[i+1]; ss = nums[i+2]; break; }
  }
  if(mo < 0 || day < 0 || yr < 0)
    return -1;
  {
    struct tm tm;
    memset(&tm, 0, sizeof tm);
    tm.tm_mday = day; tm.tm_mon = mo - 1; tm.tm_year = yr - 1900;
    tm.tm_hour = hh < 0 ? 0 : hh;
    tm.tm_min = mi < 0 ? 0 : mi;
    tm.tm_sec = ss < 0 ? 0 : ss;
    tm.tm_isdst = -1;
    return (long long)mktime(&tm);
  }
}

static void cook_add(const char *domain, const char *path, const char *name,
                     const char *value, long long expiry, int secure)
{
  Cookie *c;
  /* replace an identical (domain, path, name) first */
  for(int i = 0; i < g_ncookies; i++) {
    c = &g_jar[i];
    if(!strcasecmp(c->domain, domain) && !strcmp(c->path, path) &&
       !strcmp(c->name, name)) {
      snprintf(c->value, sizeof c->value, "%s", value);
      c->expiry = expiry;
      c->secure = secure;
      c->alive = 1;
      return;
    }
  }
  if(g_ncookies >= MAX_COOKIES)
    return;
  c = &g_jar[g_ncookies++];
  memset(c, 0, sizeof *c);
  snprintf(c->domain, sizeof c->domain, "%s", domain);
  snprintf(c->path, sizeof c->path, "%s", path[0] ? path : "/");
  snprintf(c->name, sizeof c->name, "%s", name);
  snprintf(c->value, sizeof c->value, "%s", value);
  c->expiry = expiry;
  c->secure = secure;
  c->alive = 1;
}

/* drop cookies that have expired */
static void cookie_purge(void)
{
  long long now = cookie_now();
  for(int i = 0; i < g_ncookies; i++)
    if(g_jar[i].expiry && g_jar[i].expiry < now)
      g_jar[i].alive = 0;
}

/* parse one Set-Cookie header value (also used per response header) */
static void cookie_handle_set(const char *host, const char *path,
                              const char *set)
{
  char name[256], value[1024], domain[256], cpath[512], kv[2048];
  const char *p = set, *semi;
  long long maxage = -1, expires = 0, ex;
  int secure = 0, nq;
  name[0] = value[0] = domain[0] = cpath[0] = 0;
  while(*p == ' ' || *p == '\t') p++;
  semi = strchr(p, ';');
  nq = (int)(semi ? (size_t)(semi - p) : strlen(p));
  if(nq > 2047) nq = 2047;
  memcpy(kv, p, (size_t)nq); kv[nq] = 0;
  {
    char *eq = strchr(kv, '=');
    char *pn = kv;
    if(!eq)
      return;
    *eq = 0;
    while(*pn == ' ' || *pn == '\t') pn++;
    snprintf(name, sizeof name, "%s", pn);
    snprintf(value, sizeof value, "%.*s",
             (int)sizeof(value) - 1, eq + 1);
  }
  while(semi) {
    char *k, *v, *eq;
    p = semi + 1;
    while(*p == ' ' || *p == '\t') p++;
    semi = strchr(p, ';');
    nq = (int)(semi ? (size_t)(semi - p) : strlen(p));
    if(nq > 2047) nq = 2047;
    memcpy(kv, p, (size_t)nq); kv[nq] = 0;
    eq = strchr(kv, '=');
    k = kv;
    if(eq) { *eq = 0; v = eq + 1; } else v = NULL;
    while(*k == ' ' || *k == '\t') k++;
    if(v) while(*v == ' ' || *v == '\t') v++;
    if(!strcasecmp(k, "domain"))
      snprintf(domain, sizeof domain, "%.*s", (int)sizeof(domain) - 1, v);
    else if(!strcasecmp(k, "path"))
      snprintf(cpath, sizeof cpath, "%.*s", (int)sizeof(cpath) - 1, v);
    else if(!strcasecmp(k, "secure"))
      secure = 1;
    else if(!strcasecmp(k, "max-age"))
      maxage = atoll(v);
    else if(!strcasecmp(k, "expires")) {
      expires = cookie_parse_date(v);
      if(expires < 0) expires = 0;
    }
  }
  if(!domain[0])
    snprintf(domain, sizeof domain, "%s", host);
  if(!cpath[0]) {
    const char *sl = strrchr(path, '/');
    if(sl && sl[1]) {
      size_t d = (size_t)(sl - path) + 1;
      size_t m = d < sizeof cpath - 1 ? d : sizeof cpath - 1;
      memcpy(cpath, path, m); cpath[m] = 0;
    }
    else
      snprintf(cpath, sizeof cpath, "/");
  }
  /* a leading dot on domain attribute is fine to keep */
  if(domain[0] == '.')
    memmove(domain, domain + 1, strlen(domain));
  if(maxage >= 0)
    ex = cookie_now() + maxage;
  else if(expires > 0)
    ex = expires;
  else
    ex = 0;
  if(ex && ex < cookie_now())
    return;              /* already-expired cookie: ignore */
  if(maxage == 0)
    return;              /* immediate deletion: skip */
  cook_add(domain, cpath, name, value, ex, secure);
}

/* Netscape cookie jar: load */
static void cookie_jar_load(const char *file)
{
  FILE *f = fopen(file, "r");
  char line[4096];
  if(!f)
    return;
  while(fgets(line, sizeof line, f)) {
    char d[256], p[512], n[256], v[1024], flag[16], sec[16], ex[32];
    int nf = sscanf(line, "%255s %15s %511s %15s %31s %255s %1023s",
                    d, flag, p, sec, ex, n, v);
    if(nf == 7 && *d != '#') {
      long long expiry = (long long)strtoll(ex, NULL, 10);
      if((expiry && expiry >= cookie_now()) || (!expiry && !strcmp(flag, "FALSE"))) {
        if(!strcmp(n, "#HttpOnly_") || strstr(d, "#HttpOnly_") == d) {
        }
        cook_add(d, p, n, v, expiry, !strcmp(sec, "TRUE") ? 1 : 0);
      }
    }
  }
  fclose(f);
}

/* Netscape cookie jar: save */
static void cookie_jar_save(const char *file)
{
  FILE *f;
  char tmp[2100];
  cookie_purge();
  snprintf(tmp, sizeof tmp, "%s.XXXXXX", file);
  {
    int fd = mkstemp(tmp);
    if(fd < 0)
      f = fopen(file, "w");
    else {
      f = fdopen(fd, "w");
      if(!f) { close(fd); return; }
    }
  }
  fprintf(f, "# Netscape HTTP Cookie File\n");
  fprintf(f, "# Generated by volley. Edit at your own risk.\n\n");
  for(int i = 0; i < g_ncookies; i++) {
    Cookie *c = &g_jar[i];
    char line[2048], dom[300];
    if(!c->alive)
      continue;
    if(g_sess_only && !c->expiry)
      continue;
    snprintf(dom, sizeof dom, "%s", c->domain);
    if(c->expiry)
      fprintf(f, ".%s\tTRUE\t%s\t%s\t%lld\t%s\t%s\n",
              dom, c->path, c->secure ? "TRUE" : "FALSE",
              c->expiry, c->name, c->value);
    else
      fprintf(f, ".%s\tFALSE\t%s\t%s\t0\t%s\t%s\n",
              dom, c->path, c->secure ? "TRUE" : "FALSE",
              c->name, c->value);
    (void)line;
  }
  if(f != (FILE *)-1 || f) {
    fflush(f);
    if(!strstr(tmp, ".XXXXXX")) {
      fclose(f);
      rename(tmp, file);
    }
  }
}

/* build the Cookie header for a request. Returns malloc'd string or NULL. */
static char *cookie_header(const char *host, const char *path, int is_secure)
{
  static char buf[65536];
  size_t off = 0;
  cookie_purge();
  if(g_cook_in[0]) {
    snprintf(buf, sizeof buf, "%s", g_cook_in);
    return buf;
  }
  for(int i = 0; i < g_ncookies; i++) {
    Cookie *c = &g_jar[i];
    size_t need;
    if(!c->alive)
      continue;
    if(c->secure && !is_secure)
      continue;
    if(!cookie_domain_match(c->domain, host))
      continue;
    if(!cookie_path_match(c->path, path))
      continue;
    if(c->expiry && c->expiry < cookie_now())
      continue;
    need = strlen(c->name) + strlen(c->value) + 3;
    if(off + need < sizeof buf) {
      int nw = snprintf(buf + off, sizeof buf - off, "%s%s=%s",
                        off ? "; " : "", c->name, c->value);
      if(nw > 0)
        off += (size_t)nw;
    }
  }
  if(!off)
    return NULL;
  return buf;
}

/* ---------------------------------------------------------------- */
/* netrc                                                             */
/* ---------------------------------------------------------------- */
static int netrc_lookup(const char *host, char *user, size_t unsz,
                        char *pass, size_t psz)
{
  const char *home = getenv("HOME");
  const char *npath = getenv("NETRC");
  char path[1024], line[1024];
  FILE *f;
  int machine = 0, user_ok = 0, pass_ok = 0;
  user[0] = pass[0] = 0;
  if(npath && *npath)
    snprintf(path, sizeof path, "%s", npath);
  else if(home && *home)
    snprintf(path, sizeof path, "%s/.netrc", home);
  else
    return 0;
  f = fopen(path, "r");
  if(!f)
    return 0;
  while(fgets(line, sizeof line, f)) {
    char *p = line, tok[256];
    while(*p) {
      while(*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
      if(*p == '#') break;
      if(sscanf(p, "%255s", tok) != 1) break;
      while(*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
      if(!strcmp(tok, "machine") || !strcmp(tok, "default")) {
        /* default is a special keyword with NO value in ~... actually "default" */
        if(!strcmp(tok, "default")) {
          machine = 1;
          continue;
        }
        if(sscanf(p, "%255s", tok) != 1) { machine = 0; continue; }
        while(*p && *p != ' ' && *p != '\t') p++;
        machine = !strcmp(tok, host);
        user_ok = pass_ok = 0;
      }
      else if(machine && !strcmp(tok, "login")) {
        if(sscanf(p, "%255s", tok) == 1) {
          while(*p && *p != ' ' && *p != '\t') p++;
          if(strlen(tok) < unsz) {
            strcpy(user, tok);
            user_ok = 1;
          }
        }
      }
      else if(machine && !strcmp(tok, "password")) {
        if(sscanf(p, "%255s", tok) == 1) {
          while(*p && *p != ' ' && *p != '\t') p++;
          if(strlen(tok) < psz) {
            strcpy(pass, tok);
            pass_ok = 1;
          }
        }
      }
    }
    if(user_ok && pass_ok) {
      fclose(f);
      return 1;
    }
  }
  fclose(f);
  return user_ok && pass_ok;
}

/* ---------------------------------------------------------------- */
/* environment proxies (http_proxy / https_proxy / no_proxy)         */
/* ---------------------------------------------------------------- */
static char g_no_proxy[2048];
static int  g_proxy_env = 0;   /* proxy came from the environment */

/* does the no_proxy list cover host? */
static int no_proxy_covers(const char *host)
{
  char *p, *toksave = NULL;
  if(!g_no_proxy[0])
    return 0;
  for(p = g_no_proxy; ; p = NULL) {
    char *t = strtok_r(p, ", ", &toksave);
    if(!t)
      break;
    if(!strcmp(t, "*"))
      return 1;
    if(t[0] == '.')
      t++;
    if(!strcasecmp(t, host))
      return 1;
    {
      size_t tl = strlen(t), hl = strlen(host);
      if(hl > tl && !strcasecmp(host + hl - tl, t) && host[hl - tl - 1] == '.')
        return 1;
    }
  }
  return 0;
}

typedef struct {
  int fd;
  SSL *ssl;
  int used;       /* reserved by a caller */
  int dead;       /* dead/closed marker */
  char host[256];
  char port[8];
  int https;
  int insecure;
  int ptype;      /* proxy used to reach this connection */
  int ps5h;
  char phost[256];
  char pport[8];
  int alpn;       /* 0 not negotiated, 1 h2, 2 http/1.1 */
} Conn;

static Conn g_pool[VOLLEY_MAX_POOL];
static pthread_mutex_t g_pmu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_pcv = PTHREAD_COND_INITIALIZER;

/* wait on fd events; 0 ready, -2 timeout, -1 error */
static int wfd(int fd, short events, long secs)
{
  struct pollfd pfd;
  int r;
  for(;;) {
    pfd.fd = fd;
    pfd.events = events;
    pfd.revents = 0;
    r = poll(&pfd, 1, secs > 0 ? (int)(secs * 1000) : -1);
    if(r < 0 && errno == EINTR)
      continue;
    break;
  }
  if(r == 0)
    return -2;
  if(r < 0)
    return -1;
  return 0;
}

/* read up to len bytes; >0 read, 0 EOF, -1 error, -2 timeout */
static ssize_t c_read(Conn *c, void *buf, size_t len)
{
  if(c->ssl) {
    for(;;) {
      if(!SSL_pending(c->ssl)) {
        if(wfd(c->fd, POLLIN, g_timeout) != 0)
          return -2;
      }
      {
        int r = SSL_read(c->ssl, buf, (int)len);
        if(r > 0)
          return r;
        {
          int e = SSL_get_error(c->ssl, r);
          if(e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
            short ev = (e == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
            if(wfd(c->fd, ev, g_timeout) != 0)
              return -2;
            continue;
          }
          if(e == SSL_ERROR_ZERO_RETURN)
            return 0;
          return -1;
        }
      }
    }
  }
  if(wfd(c->fd, POLLIN, g_timeout) != 0)
    return -2;
  return recv(c->fd, buf, len, MSG_NOSIGNAL);
}

/* write everything; 0 ok, -1 error */
static int c_write_all(Conn *c, const void *buf, size_t len)
{
  const char *p = (const char *)buf;
  size_t left = len;
  while(left) {
    if(c->ssl) {
      int r;
      if(wfd(c->fd, POLLOUT, g_timeout) != 0)
        return -1;
      r = SSL_write(c->ssl, p, (int)left);
      if(r > 0) {
        p += r;
        left -= (size_t)r;
        continue;
      }
      {
        int e = SSL_get_error(c->ssl, r);
        if(e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
          short ev = (e == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
          if(wfd(c->fd, ev, g_timeout) != 0)
            return -1;
          continue;
        }
        return -1;
      }
    }
    else {
      ssize_t r = send(c->fd, p, left, MSG_NOSIGNAL);
      if(r > 0) {
        p += r;
        left -= (size_t)r;
        continue;
      }
      if(r < 0 && errno == EINTR)
        continue;
      return -1;
    }
  }
  return 0;
}

/* raw socket I/O used by the proxy helpers */
static ssize_t raw_read(int fd, void *buf, size_t n)
{
  if(wfd(fd, POLLIN, g_timeout) != 0)
    return -2;
  return recv(fd, buf, n, MSG_NOSIGNAL);
}

static int raw_write_all(int fd, const void *buf, size_t n)
{
  const char *p = (const char *)buf;
  while(n) {
    ssize_t r;
    if(wfd(fd, POLLOUT, g_timeout) != 0)
      return -1;
    r = send(fd, p, n, MSG_NOSIGNAL);
    if(r > 0) {
      p += r;
      n -= (size_t)r;
    }
    else if(r < 0 && errno == EINTR)
      continue;
    else
      return -1;
  }
  return 0;
}

static int raw_read_fully(int fd, void *buf, size_t n)
{
  char *p = (char *)buf;
  while(n) {
    ssize_t r = raw_read(fd, p, n);
    if(r <= 0)
      return -1;
    p += r;
    n -= (size_t)r;
  }
  return 0;
}

static int raw_line(int fd, char *out, size_t cap)
{
  size_t i = 0;
  for(;;) {
    char c;
    ssize_t r = raw_read(fd, &c, 1);
    if(r != 1)
      return -1;
    if(c == '\n') {
      if(i && out[i-1] == '\r')
        i--;
      out[i] = 0;
      return 0;
    }
    if(i + 1 < cap)
      out[i++] = c;
  }
}

/* HTTP CONNECT through a forward proxy; 0 ok, -1 error */
static int proxy_connect(int fd, const char *host, const char *port)
{
  char b[1024];
  char line[1024];
  int code = 0;

  snprintf(b, sizeof b, "CONNECT %s:%s HTTP/1.1\r\n"
                        "Host: %s:%s\r\n", host, port, host, port);
  if(g_proxy.auth[0]) {
    char b64[700];
    base64_encode((const unsigned char *)g_proxy.auth,
                  strlen(g_proxy.auth), b64);
    snprintf(b + strlen(b), sizeof b - strlen(b),
             "Proxy-Authorization: Basic %s\r\n", b64);
  }
  snprintf(b + strlen(b), sizeof b - strlen(b),
           "Proxy-Connection: keep-alive\r\n\r\n");

  if(raw_write_all(fd, b, strlen(b)) != 0)
    return -1;
  if(raw_line(fd, line, sizeof line) != 0)
    return -1;
  sscanf(line, "HTTP/%*s %d", &code);
  if(code < 200 || code >= 300)
    return -1;
  while(raw_line(fd, line, sizeof line) == 0) {
    if(!line[0])
      break;
  }
  return 0;
}

/* SOCKS5 (RFC 1928) + username/password auth (RFC 1929) */
static int socks5_open(int fd, const char *host, const char *port, int s5h)
{
  unsigned char b[560];
  size_t idx = 0;
  int nport = atoi(port);

  b[0] = 5;
  b[1] = 1;
  b[2] = g_proxy.auth[0] ? 0x02 : 0x00;
  if(raw_write_all(fd, b, 3) != 0)
    return -1;
  if(raw_read_fully(fd, b, 2) != 0)
    return -1;
  if(b[0] != 5)
    return -1;
  if(b[1] == 0x02) {
    char *user = g_proxy.auth;
    char *pw = strchr(user, ':');
    int ul, pl;
    if(!pw)
      return -1;
    *pw = 0;
    pw++;
    ul = (int)strlen(user);
    pl = (int)strlen(pw);
    idx = 0;
    b[idx++] = 1;
    b[idx++] = (unsigned char)ul;
    memcpy(b + idx, user, (size_t)ul); idx += (size_t)ul;
    b[idx++] = (unsigned char)pl;
    memcpy(b + idx, pw, (size_t)pl); idx += (size_t)pl;
    if(raw_write_all(fd, b, idx) != 0)
      return -1;
    if(raw_read_fully(fd, b, 2) != 0)
      return -1;
    if(b[1] != 0)
      return -1;
  }
  else if(b[1] != 0x00)
    return -1;

  idx = 0;
  b[idx++] = 5;
  b[idx++] = 1;  /* CONNECT */
  b[idx++] = 0;
  if(!s5h) {
    /* resolve locally; prefer IPv4, fall back to IPv6 */
    struct addrinfo hi, *ar = NULL;
    int got = 0;
    memset(&hi, 0, sizeof hi);
    hi.ai_family = AF_UNSPEC;
    hi.ai_socktype = SOCK_STREAM;
    if(getaddrinfo(host, NULL, &hi, &ar) != 0)
      return -1;
    for(struct addrinfo *rp = ar; rp; rp = rp->ai_next) {
      if(rp->ai_family == AF_INET) {
        b[idx++] = 1;
        memcpy(b + idx, &((struct sockaddr_in *)rp->ai_addr)->sin_addr, 4);
        idx += 4;
        got = 1;
        break;
      }
      if(rp->ai_family == AF_INET6) {
        b[idx++] = 4;
        memcpy(b + idx, &((struct sockaddr_in6 *)rp->ai_addr)->sin6_addr, 16);
        idx += 16;
        got = 1;
        break;
      }
    }
    freeaddrinfo(ar);
    if(!got)
      return -1;
  }
  else {
    size_t hl = strlen(host);
    if(hl > 255)
      return -1;
    b[idx++] = 3;
    b[idx++] = (unsigned char)hl;
    memcpy(b + idx, host, hl); idx += hl;
  }
  b[idx++] = (unsigned char)((nport >> 8) & 0xff);
  b[idx++] = (unsigned char)(nport & 0xff);
  if(raw_write_all(fd, b, idx) != 0)
    return -1;

  if(raw_read_fully(fd, b, 4) != 0)
    return -1;
  if(b[0] != 5 || b[1] != 0)
    return -1;
  {
    size_t need = 0;
    if(b[3] == 1)      need = 4;
    else if(b[3] == 4) need = 16;
    else if(b[3] == 3) {
      if(raw_read_fully(fd, b + 4, 1) != 0)
        return -1;
      need = (size_t)b[4];
    }
    else
      return -1;
    if(need) {
      if(raw_read_fully(fd, b + 4, need + 2) != 0)
        return -1;
    }
    else if(raw_read_fully(fd, b + 4, 2) != 0)
      return -1;
  }
  return 0;
}

/* open a socket (plus TLS if https); 0 ok, -1 error */
static int conn_open(Conn *v, const char *host, const char *port,
                     int https, int insecure)
{
  struct addrinfo hints, *res = NULL, *rp;
  const char *chost, *cport;
  int thru = 0;           /* socket goes through a proxy */
  int sfd = -1;
  double t0 = now_ms();
  char ip[64] = "?";

  if(g_proxy.type && !(g_proxy_env && no_proxy_covers(host))) {
    chost = g_proxy.host;
    cport = g_proxy.port;
    thru = 1;
  }
  else {
    chost = host;
    cport = port;
  }

  memset(&hints, 0, sizeof hints);
  hints.ai_family = g_af == 4 ? AF_INET : g_af == 6 ? AF_INET6 : AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  if(getaddrinfo(chost, cport, &hints, &res) != 0)
    return -1;

  for(rp = res; rp; rp = rp->ai_next) {
    int fl;
    sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if(sfd < 0)
      continue;
    fl = fcntl(sfd, F_GETFL, 0);
    fcntl(sfd, F_SETFL, fl | O_NONBLOCK);
    if(connect(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
      break;
    if(errno == EINPROGRESS) {
      struct pollfd pfd;
      int r;
      long cto = g_conn_timeout > 0 ? g_conn_timeout :
                (g_timeout > 0 ? g_timeout : 10000);
      pfd.fd = sfd;
      pfd.events = POLLOUT;
      pfd.revents = 0;
      do {
        r = poll(&pfd, 1, (int)(cto * 1000));
      } while(r < 0 && errno == EINTR);
      if(r == 1) {
        int soerr = 0;
        socklen_t sl = sizeof soerr;
        getsockopt(sfd, SOL_SOCKET, SO_ERROR, &soerr, &sl);
        if(soerr == 0)
          break;
      }
    }
    close(sfd);
    sfd = -1;
  }
  if(sfd >= 0 && rp && rp->ai_addr) {
    void *addr = NULL;
    if(rp->ai_family == AF_INET)
      addr = &((struct sockaddr_in *)rp->ai_addr)->sin_addr;
    else if(rp->ai_family == AF_INET6)
      addr = &((struct sockaddr_in6 *)rp->ai_addr)->sin6_addr;
    if(addr)
      inet_ntop(rp->ai_family, addr, ip, sizeof ip);
  }
  freeaddrinfo(res);
  if(sfd < 0)
    return -1;

  /* through a proxy: tunnel now */
  if(thru && g_proxy.type) {
    if(g_proxy.type == 2) {
      if(socks5_open(sfd, host, port, g_proxy.s5h) != 0) {
        close(sfd);
        return -1;
      }
    }
    else if(https) {
      if(proxy_connect(sfd, host, port) != 0) {
        close(sfd);
        return -1;
      }
    }
  }

  fcntl(sfd, F_SETFL, fcntl(sfd, F_GETFL, 0) & ~O_NONBLOCK);
  {
    int one = 1;
    setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
  }

  if(https) {
    v->ssl = SSL_new(g_ctx);
    if(!v->ssl) {
      close(sfd);
      return -1;
    }
    SSL_set_fd(v->ssl, sfd);
    SSL_set_tlsext_host_name(v->ssl, host);
    if(g_alpn_h2 && !thru) {
      static const unsigned char proto[] = { 2, 'h', '2',
                                             8, 'h', 't', 't', 'p', '/',
                                             '1', '.', '1' };
      SSL_set_alpn_protos(v->ssl, proto, (unsigned)sizeof proto);
    }
    if(insecure) {
      SSL_set_verify(v->ssl, SSL_VERIFY_NONE, NULL);
    }
    else {
      SSL_set1_host(v->ssl, host);
      SSL_set_hostflags(v->ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    }
    for(;;) {
      int r = SSL_connect(v->ssl);
      if(r == 1)
        break;
      {
        int e = SSL_get_error(v->ssl, r);
        if(e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
          short ev = (e == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
          if(wfd(sfd, ev, g_conn_timeout > 0 ? g_conn_timeout : g_timeout) != 0) {
            SSL_free(v->ssl);
            v->ssl = NULL;
            close(sfd);
            return -1;
          }
          continue;
        }
        SSL_free(v->ssl);
        v->ssl = NULL;
        close(sfd);
        return -1;
      }
    }
    v->alpn = 0;
    if(g_alpn_h2) {
      const unsigned char *sel = NULL;
      unsigned selen = 0;
      SSL_get0_alpn_selected(v->ssl, &sel, &selen);
      if(sel && selen == 2 && sel[0] == 'h' && sel[1] == '2')
        v->alpn = 1;
      else if(sel)
        v->alpn = 2;
    }
  }

  v->fd = sfd;
  snprintf(v->host, sizeof v->host, "%s", host);
  snprintf(v->port, sizeof v->port, "%s", port);
  v->https = https;
  v->insecure = insecure;
  v->ptype = g_proxy.type;
  v->ps5h = g_proxy.s5h;
  snprintf(v->phost, sizeof v->phost, "%s", g_proxy.host);
  snprintf(v->pport, sizeof v->pport, "%s", g_proxy.port);
  v->dead = 0;

  if(g_verbose)
    fprintf(stderr, "%svolley> connected to %s (%s):%s [%s] in %.0fms%s\n",
            CD, host, ip, port, https ? "TLS" : "TCP", now_ms() - t0, CK);
  return 0;
}

/* grab a connection from the pool (or open one); NULL on failure */
static Conn *pool_get(const char *host, const char *port, int https, int insecure)
{
  int i;
  pthread_mutex_lock(&g_pmu);
  for(;;) {
    for(i = 0; i < VOLLEY_MAX_POOL; i++) {
      Conn *c = &g_pool[i];
      if(!c->used && !c->dead && c->fd >= 0 &&
         !strcmp(c->host, host) && !strcmp(c->port, port) &&
         c->https == https && c->insecure == insecure &&
         c->ptype == g_proxy.type && c->ps5h == g_proxy.s5h &&
         !strcmp(c->phost, g_proxy.host) && !strcmp(c->pport, g_proxy.port)) {
        c->used = 1;
        pthread_mutex_unlock(&g_pmu);
        if(g_verbose)
          fprintf(stderr, "%svolley> reused connection to %s:%s%s\n",
                  CD, host, port, CK);
        return c;
      }
    }
    for(i = 0; i < VOLLEY_MAX_POOL; i++) {
      Conn *c = &g_pool[i];
      if(!c->used && c->fd < 0) {
        memset(c, 0, sizeof *c);
        c->used = 1;
        c->fd = -1;
        pthread_mutex_unlock(&g_pmu);
        if(conn_open(c, host, port, https, insecure) != 0) {
          pthread_mutex_lock(&g_pmu);
          c->used = 0;
          c->fd = -1;
          c->dead = 0;
          pthread_cond_broadcast(&g_pcv);
          pthread_mutex_unlock(&g_pmu);
          return NULL;
        }
        return c;
      }
    }
    pthread_cond_wait(&g_pcv, &g_pmu);
  }
}

/* give a connection back; reusable = 1 keeps it alive for later */
static void pool_put(Conn *v, int reusable)
{
  pthread_mutex_lock(&g_pmu);
  if(!reusable && v->fd >= 0) {
    if(v->ssl)
      SSL_free(v->ssl);
    close(v->fd);
    v->ssl = NULL;
    v->fd = -1;
    v->dead = 0;
  }
  v->used = 0;
  pthread_cond_broadcast(&g_pcv);
  pthread_mutex_unlock(&g_pmu);
}

/* drop every pooled connection (used before retries) */
static void pool_flush_all(void)
{
  pthread_mutex_lock(&g_pmu);
  for(int i = 0; i < VOLLEY_MAX_POOL; i++) {
    Conn *v = &g_pool[i];
    if(v->fd >= 0) {
      if(v->ssl)
        SSL_free(v->ssl);
      close(v->fd);
      v->ssl = NULL;
      v->fd = -1;
      v->dead = 0;
    }
  }
  pthread_cond_broadcast(&g_pcv);
  pthread_mutex_unlock(&g_pmu);
}

/* ---------------------------------------------------------------- */
/* buffered reader on a connection (keeps leftover bytes)            */
/* ---------------------------------------------------------------- */
typedef struct {
  Conn *c;
  char buf[VOLLEY_LINE];
  int n, pos;
} BR;

static int br_fill(BR *b)
{
  ssize_t r;
  if(b->pos < b->n)
    return 0;
  b->pos = 0;
  b->n = 0;
  r = c_read(b->c, b->buf, sizeof b->buf);
  if(r > 0) {
    b->n = (int)r;
    return 0;
  }
  if(r == -2)
    return -2;
  return -1;
}

static int br_readn(BR *b, void *dst, size_t len)
{
  size_t got = 0;
  while(got < len) {
    if(b->pos < b->n) {
      size_t avail = (size_t)(b->n - b->pos);
      size_t take = len - got;
      if(take > avail)
        take = avail;
      memcpy((char *)dst + got, b->buf + b->pos, take);
      b->pos += (int)take;
      got += take;
      continue;
    }
    {
      int e = br_fill(b);
      if(e != 0)
        return e;
    }
  }
  return 0;
}

static int br_line(BR *b, char *out, size_t cap)
{
  size_t used = 0;
  for(;;) {
    if(b->pos < b->n) {
      char ch = b->buf[b->pos++];
      if(ch == '\n') {
        if(used >= cap)
          used = cap - 1;
        out[used] = 0;
        return 0;
      }
      if(used + 1 < cap)
        out[used++] = ch;
      continue;
    }
    {
      int e = br_fill(b);
      if(e != 0)
        return e;
    }
  }
}

/* ---------------------------------------------------------------- */
/* response headers                                                  */
/* ---------------------------------------------------------------- */
typedef struct {
  int code;
  char reason[256];
  char version[32];
  int n;
  char key[VOLLEY_MAX_HDRS][128];
  char val[VOLLEY_MAX_HDRS][1024];
  long long clen;
  int has_clen;
  int chunked;
  int conn_close;
  char location[2048];
  char content_range[256];
  char content_encoding[64];
} RespHeaders;

static int read_headers(BR *b, RespHeaders *h)
{
  char line[VOLLEY_LINE];
  int e;

  memset(h, 0, sizeof *h);

  e = br_line(b, line, sizeof line);
  if(e != 0)
    return e;
  {
    size_t l = strlen(line);
    if(l && line[l-1] == '\r')
      line[--l] = 0;
  }
  if(!strncmp(line, "HTTP/", 5)) {
    char v[32] = {0};
    int c = 0;
    int got = sscanf(line, "HTTP/%31s %3d %255[^\r]", v, &c, h->reason);
    if(got >= 2) {
      snprintf(h->version, sizeof h->version, "%s", v);
      h->code = c;
      if(got < 3)
        h->reason[0] = 0;
    }
  }
  else
    h->code = 0;

  for(;;) {
    e = br_line(b, line, sizeof line);
    if(e != 0)
      return e;
    {
      size_t l = strlen(line);
      if(l && line[l-1] == '\r')
        line[--l] = 0;
    }
    if(!line[0])
      break;
    {
      char *colon = strchr(line, ':');
      char *v;
      if(!colon)
        continue;
      *colon = 0;
      v = colon + 1;
      while(*v == ' ')
        v++;
      if(h->n < VOLLEY_MAX_HDRS) {
        snprintf(h->key[h->n], 128, "%s", line);
        snprintf(h->val[h->n], 1024, "%s", v);
        h->n++;
      }
      if(!strcasecmp(line, "content-length")) {
        h->clen = atoll(v);
        h->has_clen = 1;
      }
      else if(!strcasecmp(line, "transfer-encoding")) {
        if(strcasestr(v, "chunked"))
          h->chunked = 1;
      }
      else if(!strcasecmp(line, "connection")) {
        if(strcasestr(v, "close"))
          h->conn_close = 1;
      }
      else if(!strcasecmp(line, "location")) {
        snprintf(h->location, sizeof h->location, "%s", v);
      }
      else if(!strcasecmp(line, "content-range")) {
        snprintf(h->content_range, sizeof h->content_range, "%s", v);
      }
      else if(!strcasecmp(line, "content-encoding")) {
        snprintf(h->content_encoding, sizeof h->content_encoding, "%s", v);
      }
    }
  }

  if(g_verbose) {
    fprintf(stderr, "%svolley< HTTP/%s %d %s%s\n", CD, h->version,
            h->code, h->reason, CK);
    for(int i = 0; i < h->n; i++)
      fprintf(stderr, "%svolley< %s: %s%s\n", CD, h->key[i], h->val[i], CK);
  }
  return 0;
}

/* ---------------------------------------------------------------- */
/* growable byte buffer                                              */
/* ---------------------------------------------------------------- */
typedef struct {
  char *data;
  size_t len;
  size_t cap;
} Buffer;

static int b_add(Buffer *b, const char *p, size_t n)
{
  if(b->len + n + 1 > b->cap) {
    size_t ncap = b->cap ? b->cap * 2 : VOLLEY_IO;
    while(ncap < b->len + n + 1)
      ncap *= 2;
    {
      char *nd = realloc(b->data, ncap);
      if(!nd)
        return -1;
      b->data = nd;
      b->cap = ncap;
    }
  }
  memcpy(b->data + b->len, p, n);
  b->len += n;
  b->data[b->len] = 0;
  return 0;
}

/* ---------------------------------------------------------------- */
/* progress meter (stderr, \r based)                                 */
/* ---------------------------------------------------------------- */
static int g_prog = 0;

static void prog_size(void)
{
  if(!isatty(2))
    return;
  {
    struct winsize ws;
    if(ioctl(2, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 20 && ws.ws_col < 500)
      g_screen_w = ws.ws_col;
  }
}

static volatile sig_atomic_t g_winch = 0;
static void on_sigwinch(int s) { (void)s; g_winch = 1; }
static void prog_tick(void)
{
  if(g_winch) {
    g_winch = 0;
    prog_size();
  }
}

static void prog_bar_done(long long done, long long total, double el)
{
  int w;
  if(g_screen_w > 60)
    w = g_screen_w - 45;
  else
    w = 25;
  {
    char sb[16], tb[16], rb[16], et[16], b[64];
    int pct = total > 0 ? (int)(done * 100 / total) : -1;
    int fill = total > 0 ? (int)((long double)done * w / total) : 0;
    long long rate = (long long)(done / (el > 0 ? el : 1));
    if(fill > w) fill = w;
    for(int i = 0; i < w; i++) b[i] = i < fill ? '#' : '-';
    b[w] = 0;
    if(total > done && done > 0) {
      int eta = (int)(el * (total - done) / done);
      snprintf(et, sizeof et, "%d:%02d", eta / 60, eta % 60);
    }
    else
      strcpy(et, "0:00");
    fmt_size(done, sb); fmt_size(total, tb); fmt_size(rate, rb);
    fprintf(stderr, "\r%3d%% [%s] %s/%s %s/s ETA %s  ",
            pct < 0 ? 0 : pct, b, sb, tb, rb, et);
  }
}

static long long g_dot_done = 0;
static int g_dot_col = 0;
static int g_dot_started = 0;

static void prog_dot(long long done, long long total, double el)
{
  long long step = g_dot_bytes > 0 ? g_dot_bytes : 1024;
  long long slots = (done - g_dot_done) / step;
  if(slots < 0)
    slots = 0;
  for(long long i = 0; i < slots; i++) {
    g_dot_done += step;
    fputc('.', stderr);
    g_dot_col++;
    if(g_dot_col % g_dot_spacing == 0)
      fputc(' ', stderr);
    if(g_dot_col % g_dots_in_line == 0) {
      char a[16], r[16];
      fmt_size(g_dot_done, a);
      fmt_size((long long)(done / (el > 0.0001 ? el : 1.0)), r);
      fprintf(stderr, "  %-10s %5s/s\n", a, r);
      g_dot_col = 0;
    }
  }
  fflush(stderr);
  (void)total;
}

static void prog_render(long long done, long long total, double el)
{
  prog_tick();
  if(g_progstyle == 1)
    prog_dot(done, total, el);
  else
    prog_bar_done(done, total, el);
}

/* called once a (streamed) transfer ends */
static void prog_end(void)
{
  if(g_progstyle == 1 && g_prog) {
    char a[16];
    if(g_dot_col) {
      fmt_size(g_dot_done, a);
      fprintf(stderr, "  %-10s\n", a);
    }
    g_dot_col = 0;
    g_dot_started = 0;
  }
}

/* ---------------------------------------------------------------- */
/* output mutex: guards interleaving of parallel stdout writes       */
/* ---------------------------------------------------------------- */
static pthread_mutex_t g_omu = PTHREAD_MUTEX_INITIALIZER;

/* ---------------------------------------------------------------- */
/* results, options, request building                                */
/* ---------------------------------------------------------------- */
typedef struct {
  int status;               /* http code, 0 = network failure */
  long long bytes;          /* body bytes written */
  double ms;
  char err[1024];
  char final_url[2048];
  Buffer body;              /* buffered body (streaming leaves this empty) */
  int streamed;             /* body went to a file directly */
  int net_ok;               /* request/response completed cleanly */
  int http_err;             /* status >= 400 */
  long long total;          /* content-length / range total, -1 unknown */
  long long cr_first;       /* Content-Range first byte pos, -1 unknown */
  long long cr_last;        /* Content-Range last byte pos, -1 unknown */
  int cr_ok;                /* a parseable Content-Range header was present */
} Res;

typedef struct {
  const char *range;   /* extra "Range: bytes=" value, or NULL */
  FILE *stream_to;     /* stream body here (else buffer in memory) */
  int no_decode;       /* pass the raw (compressed) body through */
} XOpt;

typedef struct {
  const char *method;
  const char *path;
  const char *host;
  const char *port;
  const char *auth;
  const char *body;
  size_t body_len;
  const char *range;
  const char *useragent;
  const char *content_type;   /* override, NULL = default */
  const char *cookie;         /* prebuilt Cookie header value, NULL = none */
  char **uhdrs;
  int nuhdrs;
  int https;
  int abs_url;                /* absolute-form request target (http proxy) */
  int chunked;                /* use Transfer-Encoding: chunked */
  FILE *up_file;              /* stream request body from here (chunked) */
} Req;

typedef struct {
  char *p;
  size_t rem;
} Writer;

static void wstr(Writer *w, const char *s)
{
  size_t k = strlen(s);
  if(k > w->rem)
    k = w->rem;
  memcpy(w->p, s, k);
  w->p += k;
  w->rem -= k;
}

static void wfmt(Writer *w, const char *fmt, ...)
{
  char b[4096];
  va_list ap;
  int k;
  va_start(ap, fmt);
  k = vsnprintf(b, sizeof b, fmt, ap);
  va_end(ap);
  if(k < 0)
    k = 0;
  if((size_t)k > w->rem)
    k = (int)w->rem;
  memcpy(w->p, b, (size_t)k);
  w->p += k;
  w->rem -= k;
}

static void host_header(char *out, size_t cap, const char *host,
                        const char *port, int https)
{
  if(!strcmp(port, "443") && https)
    snprintf(out, cap, "%s", host);
  else if(!strcmp(port, "80") && !https)
    snprintf(out, cap, "%s", host);
  else
    snprintf(out, cap, "%s:%s", host, port);
}

static int send_req(Conn *c, Req *r)
{
  char head[32768];
  Writer w;
  char hp[512];
  int have_auth = r->auth && r->auth[0];
  int have_body = r->body && r->body_len;
  int ch_stream = r->chunked && (r->up_file || have_body);

  w.p = head;
  w.rem = sizeof head;

  if(r->abs_url) {
    char hp2[512];
    host_header(hp2, sizeof hp2, r->host, r->port, r->https);
    wfmt(&w, "%s http://%s%s HTTP/1.1\r\n", r->method, hp2, r->path);
  }
  else
    wfmt(&w, "%s %s HTTP/1.1\r\n", r->method, r->path);
  host_header(hp, sizeof hp, r->host, r->port, r->https);
  wfmt(&w, "Host: %s\r\n", hp);
  wfmt(&w, "User-Agent: %s\r\n", r->useragent ? r->useragent :
                                   "curl/8.5.0");
  wstr(&w, "Accept: */*\r\n");
  wstr(&w, "Accept-Encoding: gzip, deflate\r\n");
  if(have_auth) {
    char b64[512];
    base64_encode((const unsigned char *)r->auth, strlen(r->auth), b64);
    wfmt(&w, "Authorization: Basic %s\r\n", b64);
  }
  if(r->range)
    wfmt(&w, "Range: bytes=%s\r\n", r->range);
  if(ch_stream) {
    wstr(&w, "Transfer-Encoding: chunked\r\n");
    wfmt(&w, "Content-Type: %s\r\n", r->content_type ?
              r->content_type : "application/x-www-form-urlencoded");
  }
  else if(have_body) {
    wfmt(&w, "Content-Length: %zu\r\n", r->body_len);
    wfmt(&w, "Content-Type: %s\r\n", r->content_type ?
              r->content_type : "application/x-www-form-urlencoded");
  }
  for(int i = 0; i < r->nuhdrs; i++)
    wfmt(&w, "%s\r\n", r->uhdrs[i]);
  if(r->cookie)
    wfmt(&w, "Cookie: %s\r\n", r->cookie);
  wstr(&w, "Connection: keep-alive\r\n\r\n");

  if(g_verbose) {
    fprintf(stderr, "> ");
    for(size_t i = 0; i < (size_t)(w.p - head); i++) {
      if(head[i] == '\r')
        continue;
      fputc(head[i], stderr);
      if(head[i] == '\n')
        fprintf(stderr, "> ");
    }
    if((size_t)(w.p - head) > 0 && head[w.p - head - 1] != '\n')
      fputc('\n', stderr);
  }

  if(c_write_all(c, head, (size_t)(w.p - head)) != 0)
    return -1;
  if(ch_stream && r->up_file) {
    char cbuf[16384], siz[32];
    size_t got;
    rewind(r->up_file);
    while((got = fread(cbuf, 1, sizeof cbuf, r->up_file)) > 0) {
      int sn = snprintf(siz, sizeof siz, "%zx\r\n", got);
      if(c_write_all(c, siz, (size_t)sn) != 0 ||
         c_write_all(c, cbuf, got) != 0 ||
         c_write_all(c, "\r\n", 2) != 0)
        return -1;
    }
    if(c_write_all(c, "0\r\n\r\n", 5) != 0)
      return -1;
  }
  else if(ch_stream) {
    char siz[32];
    int sn = snprintf(siz, sizeof siz, "%zx\r\n", r->body_len);
    if(c_write_all(c, siz, (size_t)sn) != 0 ||
       c_write_all(c, r->body, r->body_len) != 0 ||
       c_write_all(c, "\r\n0\r\n\r\n", 7) != 0)
      return -1;
  }
  else if(have_body && c_write_all(c, r->body, r->body_len) != 0)
    return -1;
  return 0;
}

/* ---------------------------------------------------------------- */
/* body emission: stream to fd or grow in-memory buffer              */
/* ---------------------------------------------------------------- */
static int emit_body(int do_stream, FILE *fp, Buffer *mb,
                     const char *p, size_t n, long long *done,
                     long long ptotal, double t0)
{
  if(do_stream) {
    if(fwrite(p, 1, n, fp) != n)
      return -1;
  }
  else {
    if(b_add(mb, p, n) != 0)
      return -1;
  }
  *done += (long long)n;
  if(do_stream && g_prog)
    prog_render(*done, ptotal, now_ms() - t0);
  return 0;
}

/* ---------------------------------------------------------------- */
/* content decoding: gzip / deflate (zlib, auto-detected format)     */
/* ---------------------------------------------------------------- */
typedef struct {
  int active;
  int eof;
  z_stream z;
  char out[VOLLEY_IO];
} CDec;

static int dec_start(CDec *d, const char *enc)
{
  memset(d, 0, sizeof *d);
  if(!enc || !enc[0])
    return 0;
  if(!strcasecmp(enc, "gzip") || !strcasecmp(enc, "x-gzip") ||
     !strcasecmp(enc, "deflate")) {
    /* 15 window + 32 = auto-detect gzip or raw zlib stream */
    if(inflateInit2(&d->z, 15 + 32) != Z_OK)
      return -1;
    d->active = 1;
  }
  return 0;   /* unknown encodings pass through raw */
}

static void dec_fin(CDec *d)
{
  if(d->active)
    inflateEnd(&d->z);
}

/* feed raw bytes through the decoder into emit_body; -1 io/oom, -2 corrupt */
static int dec_push(CDec *d, const char *in, size_t inlen, int do_stream,
                    FILE *fp, Buffer *mb, long long *done, double t0)
{
  if(!d->active)
    return emit_body(do_stream, fp, mb, in, inlen, done, -1, t0);
  d->z.next_in = (Bytef *)(unsigned char *)in;
  d->z.avail_in = (uInt)inlen;
  while(d->z.avail_in && !d->eof) {
    d->z.next_out = (Bytef *)d->out;
    d->z.avail_out = (uInt)sizeof d->out;
    {
      int zr = inflate(&d->z, Z_NO_FLUSH);
      size_t have = sizeof d->out - d->z.avail_out;
      if(have && emit_body(do_stream, fp, mb, d->out, have, done, -1, t0) != 0)
        return -1;
      if(zr == Z_STREAM_END) {
        d->eof = 1;
        break;
      }
      if(zr != Z_OK && zr != Z_BUF_ERROR)
        return -2;
    }
  }
  return 0;
}

/* flush any remaining decoded bytes once the wire stream is exhausted */
static int dec_finish(CDec *d, int do_stream, FILE *fp, Buffer *mb,
                      long long *done, double t0)
{
  int dfail = 0;
  if(!d->active || d->eof)
    return 0;
  for(;;) {
    d->z.next_out = (Bytef *)d->out;
    d->z.avail_out = (uInt)sizeof d->out;
    {
      int zr = inflate(&d->z, Z_FINISH);
      size_t have = sizeof d->out - d->z.avail_out;
      if(have && emit_body(do_stream, fp, mb, d->out, have, done, -1, t0) != 0)
        return -1;
      if(zr == Z_STREAM_END) {
        d->eof = 1;
        break;
      }
      if(zr != Z_OK && zr != Z_BUF_ERROR) {
        dfail = -2;
        break;
      }
    }
  }
  return dfail;
}

/* read the response body; returns bytes read, or -1 on failure */
static long long read_body(BR *br, RespHeaders *h, XOpt *xo, Res *res)
{
  long long done = 0;
  double t0 = now_ms();
  int do_stream = xo->stream_to != NULL;
  FILE *fp = xo->stream_to;
  Buffer mb;
  int fail = 0;
  CDec dec;

  if(*h->content_encoding && !xo->no_decode) {
    if(dec_start(&dec, h->content_encoding) != 0) {
      snprintf(res->err, sizeof res->err, "failed to init decoder");
      return -1;
    }
  }
  else
    memset(&dec, 0, sizeof dec);

  memset(&mb, 0, sizeof mb);

  if(h->chunked) {
    for(;;) {
      char line[256];
      int e = br_line(br, line, sizeof line);
      long sz;
      if(e != 0) {
        fail = 2;
        break;
      }
      {
        char *semi = strchr(line, ';');
        if(semi)
          *semi = 0;
      }
      sz = strtol(line, NULL, 16);
      if(sz == 0) {
        while(br_line(br, line, sizeof line) == 0) {
          if(!line[0] || line[0] == '\r' || line[0] == '\n')
            break;
        }
        break;
      }
      if(sz < 0 || sz > 1024LL*1024*1024) {
        fail = 2;
        break;
      }
      {
        long left = sz;
        char tmp[VOLLEY_IO];
        while(left > 0) {
          size_t want = (size_t)left < sizeof tmp ? (size_t)left : sizeof tmp;
          e = br_readn(br, tmp, want);
          if(e != 0) {
            fail = 2;
            break;
          }
          rate_pace((long long)want);
          {
            int cc = dec_push(&dec, tmp, want, do_stream, fp, &mb,
                              &done, t0);
            if(cc == -2) {
              snprintf(res->err, sizeof res->err,
                       "content decoding failed (%s)", h->content_encoding);
              fail = 1;
              break;
            }
            if(cc != 0) {
              fail = 3;
              break;
            }
          }
          left -= (long)want;
        }
        if(fail)
          break;
      }
      {
        char crlf[2];
        if(br_readn(br, crlf, 2) != 0) {
          fail = 2;
          break;
        }
      }
    }
  }
  else if(h->has_clen) {
    long long left = h->clen;
    char tmp[VOLLEY_IO];
    while(left > 0) {
      size_t want = left < (long long)sizeof tmp ? (size_t)left : sizeof tmp;
      int e = br_readn(br, tmp, want);
      if(e != 0) {
        snprintf(res->err, sizeof res->err, "%s",
                 e == -2 ? "timed out during transfer"
                         : "connection closed during transfer");
        fail = 1;
        break;
      }
      rate_pace((long long)want);
      {
        int cc = dec_push(&dec, tmp, want, do_stream, fp, &mb, &done, t0);
        if(cc == -2) {
          snprintf(res->err, sizeof res->err,
                   "content decoding failed (%s)", h->content_encoding);
          fail = 1;
          break;
        }
        if(cc != 0) {
          snprintf(res->err, sizeof res->err, "failed writing output");
          fail = 1;
          break;
        }
      }
      left -= want;
    }
  }
  else {
    /* length unknown: read until the connection closes */
    if(br->pos < br->n) {
      if(dec_push(&dec, br->buf + br->pos, (size_t)(br->n - br->pos),
                  do_stream, fp, &mb, &done, t0) != 0) {
        snprintf(res->err, sizeof res->err, "failed writing output");
        fail = 1;
      }
      br->pos = br->n;
    }
    while(!fail) {
      char tmp[VOLLEY_IO];
      ssize_t r = c_read(br->c, tmp, sizeof tmp);
      if(r > 0) {
        rate_pace((long long)r);
        int cc = dec_push(&dec, tmp, (size_t)r, do_stream, fp, &mb,
                          &done, t0);
        if(cc == -2) {
          snprintf(res->err, sizeof res->err,
                   "content decoding failed (%s)", h->content_encoding);
          fail = 1;
        }
        else if(cc != 0) {
          snprintf(res->err, sizeof res->err, "failed writing output");
          fail = 1;
        }
      }
      else if(r == 0)
        break;
      else if(r == -2) {
        snprintf(res->err, sizeof res->err, "timed out during transfer");
        fail = 1;
      }
      else {
        snprintf(res->err, sizeof res->err, "connection closed during transfer");
        fail = 1;
      }
    }
  }

  if(!fail) {
    int df = dec_finish(&dec, do_stream, fp, &mb, &done, t0);
    if(df == -2) {
      snprintf(res->err, sizeof res->err, "content decoding failed (%s)",
               h->content_encoding);
      fail = 1;
    }
    else if(df != 0) {
      snprintf(res->err, sizeof res->err, "failed writing output");
      fail = 1;
    }
  }
  dec_fin(&dec);

  res->body = mb;
  if(!res->err[0]) {
    if(fail == 2)
      snprintf(res->err, sizeof res->err, "malformed or interrupted body");
    else if(fail == 3)
      snprintf(res->err, sizeof res->err, "out of memory");
  }
  if(fail)
    return -1;
  return done;
}

/* ---------------------------------------------------------------- */
/* config + job                                                      */
/* ---------------------------------------------------------------- */
typedef struct {
  char method[16];
  char *body;
  size_t body_len;
  char **uhdrs;
  int nuhdrs;
  char auth[512];
  const char *useragent;
  int parallel;             /* -j */
  int segs;                 /* -c */
  int insecure;             /* -k */
  int follow;               /* follow redirects */
  int silent;               /* -s */
  int include_hdrs;         /* -i */
  int fail_on_http;         /* -f */
  char **urls;
  int nurls;
  const char *range;        /* optional -r */
  int head;                 /* -I */
  int ipv;                  /* 0 any, 4, 6 */
  long long resume_off;     /* -C; -1 = none, >=0 = offset */
  const char *resume_str;   /* raw -C argument */
  const char *ctype;        /* -T upload content type override */
  int no_decode;            /* --no-encoding */
  int chunked;              /* Transfer-Encoding: chunked request body */
  FILE *up_file;            /* stream the body from this file when chunked */
} Cfg;

typedef struct {
  const char *url;          /* original url */
  Url u;                    /* parsed */
  char save_path[2048];     /* "" = stdout */
} Jb;

static void resolve_auth(Cfg *cfg, Url *u, char *out, size_t cap)
{
  char nuser[256], npass[256];
  if(u->auth[0])
    snprintf(out, cap, "%s", u->auth);
  else if(cfg->auth[0])
    snprintf(out, cap, "%s", cfg->auth);
  else if(g_netrc && netrc_lookup(u->host, nuser, sizeof nuser,
                                  npass, sizeof npass))
    snprintf(out, cap, "%s:%s", nuser, npass);
  else
    out[0] = 0;
}

/* ---------------------------------------------------------------- */
/* FTP (RFC 959) and GOPHER (RFC 1436)                               */
/* ---------------------------------------------------------------- */
static int sock_connect_plain(const char *host, const char *port,
                              char *er, size_t ersz)
{
  struct addrinfo hints, *res = NULL, *rp;
  int sfd = -1;
  memset(&hints, 0, sizeof hints);
  hints.ai_family = g_af == 4 ? AF_INET : g_af == 6 ? AF_INET6 : AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  if(getaddrinfo(host, port, &hints, &res) != 0) {
    snprintf(er, ersz, "cannot resolve %s", host);
    return -1;
  }
  for(rp = res; rp; rp = rp->ai_next) {
    int fl;
    sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if(sfd < 0)
      continue;
    fl = fcntl(sfd, F_GETFL, 0);
    fcntl(sfd, F_SETFL, fl | O_NONBLOCK);
    if(connect(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
      break;
    if(errno == EINPROGRESS) {
      struct pollfd pfd;
      int r;
      long cto = g_conn_timeout > 0 ? g_conn_timeout :
                (g_timeout > 0 ? g_timeout : 10000);
      pfd.fd = sfd;
      pfd.events = POLLOUT;
      do {
        r = poll(&pfd, 1, (int)(cto * 1000));
      } while(r < 0 && errno == EINTR);
      if(r == 1) {
        int soerr = 0;
        socklen_t sl = sizeof soerr;
        getsockopt(sfd, SOL_SOCKET, SO_ERROR, &soerr, &sl);
        if(soerr == 0)
          break;
      }
    }
    close(sfd);
    sfd = -1;
  }
  freeaddrinfo(res);
  if(sfd < 0)
    snprintf(er, ersz, "cannot connect to %s:%s", host, port);
  fcntl(sfd, F_SETFL, fcntl(sfd, F_GETFL, 0) & ~O_NONBLOCK);
  return sfd;
}

static int ftp_cmd(int fd, const char *fmt, ...)
{
  char buf[1024];
  va_list ap;
  int n;
  va_start(ap, fmt);
  n = vsnprintf(buf, sizeof buf, fmt, ap);
  va_end(ap);
  if(n < 0 || n >= (int)sizeof buf)
    return -1;
  if(g_verbose)
    fprintf(stderr, "%sftp> %s%s", CD, buf, CK);
  return raw_write_all(fd, buf, (size_t)n);
}

/* read a single reply line from the control connection */
static int ftp_line(int fd, char *out, size_t cap)
{
  return raw_line(fd, out, cap);
}

/* read (potentially multi-line) replies until we get "mmm <text>" or the
   code alone; returns the numeric code. */
static int ftp_resp(int fd, char *out, size_t cap, int want)
{
  int code = 0;
  for(;;) {
    char line[1024];
    if(ftp_line(fd, line, sizeof line) != 0)
      return -1;
    code = atoi(line);
    if(out)
      snprintf(out, cap, "%s", line);
    if(code < 100 || code > 599)
      return -1;
    if(line[3] == ' ' || line[3] == 0) {
      if(want && code != want)
        return code;
      return code;
    }
    if(want && code != want && line[3] == '-') {
      /* multi-line continuation; keep reading until we get the code */
      int base = code;
      int done = 0;
      while(!done) {
        if(ftp_line(fd, line, sizeof line) != 0)
          return -1;
        if(code < 100 || code > 599)
          return -1;
        if(atoi(line) == base && line[3] == ' ') {
          done = 1;
          code = base;
        }
        else if(line[3] == ' ' || line[3] == 0) {
          code = atoi(line);
          done = 1;
        }
      }
      if(want && code != want)
        return code;
      return code;
    }
  }
}

static int ftp_login(int fd, const char *user, const char *pass)
{
  char line[1024];
  int code;
  code = ftp_resp(fd, line, sizeof line, 220);
  if(code != 220)
    return -1;
  if(!user[0])
    user = "anonymous";
  if(!pass[0])
    pass = "volley@example.com";
  if(ftp_cmd(fd, "USER %s\r\n", user) != 0)
    return -1;
  code = ftp_resp(fd, line, sizeof line, 331);
  if(code != 331 && code != 230)
    return -1;
  if(code == 331) {
    if(ftp_cmd(fd, "PASS %s\r\n", pass) != 0)
      return -1;
    code = ftp_resp(fd, line, sizeof line, 230);
    if(code != 230)
      return -1;
  }
  return 0;
}

/* parse "227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)" */
static int ftp_pasv(int fd, char *dhost, size_t dhostsz, char *dport, size_t dportsz)
{
  char line[1024];
  int code, h1, h2, h3, h4, p1, p2;
  code = ftp_cmd(fd, "PASV\r\n", 0) == 0 ? ftp_resp(fd, line, sizeof line, 227) : -1;
  if(code != 227)
    return -1;
  if(sscanf(line, "%*[^(] (%d,%d,%d,%d,%d,%d)", &h1, &h2, &h3, &h4, &p1, &p2) != 6)
    return -1;
  snprintf(dhost, dhostsz, "%d.%d.%d.%d", h1, h2, h3, h4);
  snprintf(dport, dportsz, "%d", p1 * 256 + p2);
  return 0;
}

static void ftp_do_data(int dfd, Buffer *mb)
{
  char tmp[VOLLEY_IO];
  ssize_t r;
  rate_init();
  for(;;) {
    r = wfd(dfd, POLLIN, g_timeout) != 0 ? -2 : (ssize_t)recv(dfd, tmp, sizeof tmp, MSG_NOSIGNAL);
    if(r > 0) {
      rate_pace((long long)r);
      b_add(mb, tmp, (size_t)r);
    }
    else
      break;
  }
}

/* returns 0 ok, -1 error. Fills res->body with the data. */
static int do_ftp(Cfg *cfg, Jb *jb, Res *res, const char *op,
                  const char *listkind)
{
  Url *u = &jb->u;
  char user[256] = "", pass[256] = "";
  char ctrl[256] = "", cport[8] = "21";
  char dhost[256], dport[8];
  char er[512];
  int cfd, dfd, code;
  Buffer mb;
  int only_names = !strcmp(listkind, "NLST");

  (void)cfg;
  res->bytes = 0;
  res->total = -1;
  if(u->auth[0]) {
    char *colon = strchr(u->auth, ':');
    if(colon) {
      size_t ul = (size_t)(colon - u->auth);
      if(ul >= sizeof user) ul = sizeof user - 1;
      memcpy(user, u->auth, ul); user[ul] = 0;
      snprintf(pass, sizeof pass, "%s", colon + 1);
    }
    else
      snprintf(user, sizeof user, "%s", u->auth);
  }
  snprintf(ctrl, sizeof ctrl, "%s", u->host);
  snprintf(cport, sizeof cport, "%s", u->port);
  cfd = sock_connect_plain(ctrl, cport, er, sizeof er);
  if(cfd < 0) {
    snprintf(res->err, sizeof res->err, "%s", er);
    return -1;
  }
  if(ftp_login(cfd, user, pass) != 0) {
    close(cfd);
    snprintf(res->err, sizeof res->err, "FTP login failed for %s", u->host);
    return -1;
  }
  if(ftp_pasv(cfd, dhost, sizeof dhost, dport, sizeof dport) != 0) {
    close(cfd);
    snprintf(res->err, sizeof res->err, "FTP PASV failed");
    return -1;
  }
  dfd = sock_connect_plain(dhost, dport, er, sizeof er);
  if(dfd < 0) {
    close(cfd);
    snprintf(res->err, sizeof res->err, "FTP data connection failed: %s", er);
    return -1;
  }
  if(!strcmp(op, "RETR") || !strcmp(op, "STOR")) {
    char q[2100];
    if(!strcmp(op, "STOR"))
      q[0] = 0;
    else
      q[0] = 0;
    snprintf(q, sizeof q, "%s %s\r\n", op, u->path);
    if(ftp_cmd(cfd, "%s", q) != 0) {
      close(dfd); close(cfd);
      return -1;
    }
  }
  else if(only_names)
    ftp_cmd(cfd, "NLST\r\n");
  else
    ftp_cmd(cfd, "LIST\r\n");
  code = ftp_resp(cfd, NULL, 0, 150);
  if(code != 150 && code != 125) {
    close(dfd); close(cfd);
    snprintf(res->err, sizeof res->err, "FTP server refused transfer");
    return -1;
  }
  if(!strcmp(op, "STOR")) {
    if(cfg->body && cfg->body_len) {
      size_t written = 0;
      while(written < cfg->body_len) {
        ssize_t n = send(dfd, cfg->body + written, cfg->body_len - written,
                         MSG_NOSIGNAL);
        if(n <= 0)
          break;
        written += (size_t)n;
      }
    }
    close(dfd);
    ftp_resp(cfd, NULL, 0, 226);
    ftp_cmd(cfd, "QUIT\r\n");
    close(cfd);
    memset(&mb, 0, sizeof mb);
    res->body = mb;
    res->bytes = 0;
    res->status = 200;
    res->net_ok = 1;
    return 0;
  }
  memset(&mb, 0, sizeof mb);
  ftp_do_data(dfd, &mb);
  close(dfd);
  ftp_resp(cfd, NULL, 0, 226);
  ftp_cmd(cfd, "QUIT\r\n");
  close(cfd);
  res->body = mb;
  res->bytes = (long long)mb.len;
  res->status = 200;
  res->net_ok = 1;
  return 0;
}

static void gopher_send(int fd, const char *selector)
{
  char buf[4096];
  snprintf(buf, sizeof buf, "%s\r\n", selector);
  raw_write_all(fd, buf, strlen(buf));
}

static int do_gopher(Cfg *cfg, Jb *jb, Res *res)
{
  Url *u = &jb->u;
  char er[512];
  char type = '0';
  const char *sel = "";
  int fd;
  Buffer mb;
  (void)cfg;
  {
    const char *p = u->path;
    if(*p == '/')
      p++;
    if(p[0] && p[1] == '\t') {
      type = p[0];
      sel = p + 2;
    }
    else
      sel = p;
  }
  fd = sock_connect_plain(u->host, u->port, er, sizeof er);
  if(fd < 0) {
    snprintf(res->err, sizeof res->err, "%s", er);
    return -1;
  }
  gopher_send(fd, sel);
  memset(&mb, 0, sizeof mb);
  {
    char tmp[VOLLEY_IO];
    ssize_t r;
    for(;;) {
      r = wfd(fd, POLLIN, g_timeout) != 0 ? -2 : (ssize_t)recv(fd, tmp, sizeof tmp, MSG_NOSIGNAL);
      if(r > 0)
        b_add(&mb, tmp, (size_t)r);
      else
        break;
    }
  }
  close(fd);
  /* item-type 7 (search) and plain text get raw output; others are
     passed through as-is */
  (void)type;
  res->body = mb;
  res->bytes = (long long)mb.len;
  res->status = 200;
  res->net_ok = 1;
  return 0;
}

/* ---------------------------------------------------------------- */
/* HTTP/2: minimal hand-rolled client (RFC 7540/7541)                 */
/* opt-in via --http2; GET/HEAD/POST on a single stream.              */
/* ---------------------------------------------------------------- */

/* HPACK Huffman table, RFC 7541 Appendix B */
static const struct { unsigned int code; unsigned char len; }
  huf_code[257] = {
  {0x00001ff8u, 13}, /* 0 */
  {0x007fffd8u, 23}, /* 1 */
  {0x0fffffe2u, 28}, /* 2 */
  {0x0fffffe3u, 28}, /* 3 */
  {0x0fffffe4u, 28}, /* 4 */
  {0x0fffffe5u, 28}, /* 5 */
  {0x0fffffe6u, 28}, /* 6 */
  {0x0fffffe7u, 28}, /* 7 */
  {0x0fffffe8u, 28}, /* 8 */
  {0x00ffffeau, 24}, /* 9 */
  {0x3ffffffcu, 30}, /* 10 */
  {0x0fffffe9u, 28}, /* 11 */
  {0x0fffffeau, 28}, /* 12 */
  {0x3ffffffdu, 30}, /* 13 */
  {0x0fffffebu, 28}, /* 14 */
  {0x0fffffecu, 28}, /* 15 */
  {0x0fffffedu, 28}, /* 16 */
  {0x0fffffeeu, 28}, /* 17 */
  {0x0fffffefu, 28}, /* 18 */
  {0x0ffffff0u, 28}, /* 19 */
  {0x0ffffff1u, 28}, /* 20 */
  {0x0ffffff2u, 28}, /* 21 */
  {0x3ffffffeu, 30}, /* 22 */
  {0x0ffffff3u, 28}, /* 23 */
  {0x0ffffff4u, 28}, /* 24 */
  {0x0ffffff5u, 28}, /* 25 */
  {0x0ffffff6u, 28}, /* 26 */
  {0x0ffffff7u, 28}, /* 27 */
  {0x0ffffff8u, 28}, /* 28 */
  {0x0ffffff9u, 28}, /* 29 */
  {0x0ffffffau, 28}, /* 30 */
  {0x0ffffffbu, 28}, /* 31 */
  {0x00000014u, 6}, /* 32 */
  {0x000003f8u, 10}, /* 33 */
  {0x000003f9u, 10}, /* 34 */
  {0x00000ffau, 12}, /* 35 */
  {0x00001ff9u, 13}, /* 36 */
  {0x00000015u, 6}, /* 37 */
  {0x000000f8u, 8}, /* 38 */
  {0x000007fau, 11}, /* 39 */
  {0x000003fau, 10}, /* 40 */
  {0x000003fbu, 10}, /* 41 */
  {0x000000f9u, 8}, /* 42 */
  {0x000007fbu, 11}, /* 43 */
  {0x000000fau, 8}, /* 44 */
  {0x00000016u, 6}, /* 45 */
  {0x00000017u, 6}, /* 46 */
  {0x00000018u, 6}, /* 47 */
  {0x00000000u, 5}, /* 48 */
  {0x00000001u, 5}, /* 49 */
  {0x00000002u, 5}, /* 50 */
  {0x00000019u, 6}, /* 51 */
  {0x0000001au, 6}, /* 52 */
  {0x0000001bu, 6}, /* 53 */
  {0x0000001cu, 6}, /* 54 */
  {0x0000001du, 6}, /* 55 */
  {0x0000001eu, 6}, /* 56 */
  {0x0000001fu, 6}, /* 57 */
  {0x0000005cu, 7}, /* 58 */
  {0x000000fbu, 8}, /* 59 */
  {0x00007ffcu, 15}, /* 60 */
  {0x00000020u, 6}, /* 61 */
  {0x00000ffbu, 12}, /* 62 */
  {0x000003fcu, 10}, /* 63 */
  {0x00001ffau, 13}, /* 64 */
  {0x00000021u, 6}, /* 65 */
  {0x0000005du, 7}, /* 66 */
  {0x0000005eu, 7}, /* 67 */
  {0x0000005fu, 7}, /* 68 */
  {0x00000060u, 7}, /* 69 */
  {0x00000061u, 7}, /* 70 */
  {0x00000062u, 7}, /* 71 */
  {0x00000063u, 7}, /* 72 */
  {0x00000064u, 7}, /* 73 */
  {0x00000065u, 7}, /* 74 */
  {0x00000066u, 7}, /* 75 */
  {0x00000067u, 7}, /* 76 */
  {0x00000068u, 7}, /* 77 */
  {0x00000069u, 7}, /* 78 */
  {0x0000006au, 7}, /* 79 */
  {0x0000006bu, 7}, /* 80 */
  {0x0000006cu, 7}, /* 81 */
  {0x0000006du, 7}, /* 82 */
  {0x0000006eu, 7}, /* 83 */
  {0x0000006fu, 7}, /* 84 */
  {0x00000070u, 7}, /* 85 */
  {0x00000071u, 7}, /* 86 */
  {0x00000072u, 7}, /* 87 */
  {0x000000fcu, 8}, /* 88 */
  {0x00000073u, 7}, /* 89 */
  {0x000000fdu, 8}, /* 90 */
  {0x00001ffbu, 13}, /* 91 */
  {0x0007fff0u, 19}, /* 92 */
  {0x00001ffcu, 13}, /* 93 */
  {0x00003ffcu, 14}, /* 94 */
  {0x00000022u, 6}, /* 95 */
  {0x00007ffdu, 15}, /* 96 */
  {0x00000003u, 5}, /* 97 */
  {0x00000023u, 6}, /* 98 */
  {0x00000004u, 5}, /* 99 */
  {0x00000024u, 6}, /* 100 */
  {0x00000005u, 5}, /* 101 */
  {0x00000025u, 6}, /* 102 */
  {0x00000026u, 6}, /* 103 */
  {0x00000027u, 6}, /* 104 */
  {0x00000006u, 5}, /* 105 */
  {0x00000074u, 7}, /* 106 */
  {0x00000075u, 7}, /* 107 */
  {0x00000028u, 6}, /* 108 */
  {0x00000029u, 6}, /* 109 */
  {0x0000002au, 6}, /* 110 */
  {0x00000007u, 5}, /* 111 */
  {0x0000002bu, 6}, /* 112 */
  {0x00000076u, 7}, /* 113 */
  {0x0000002cu, 6}, /* 114 */
  {0x00000008u, 5}, /* 115 */
  {0x00000009u, 5}, /* 116 */
  {0x0000002du, 6}, /* 117 */
  {0x00000077u, 7}, /* 118 */
  {0x00000078u, 7}, /* 119 */
  {0x00000079u, 7}, /* 120 */
  {0x0000007au, 7}, /* 121 */
  {0x0000007bu, 7}, /* 122 */
  {0x00007ffeu, 15}, /* 123 */
  {0x000007fcu, 11}, /* 124 */
  {0x00003ffdu, 14}, /* 125 */
  {0x00001ffdu, 13}, /* 126 */
  {0x0ffffffcu, 28}, /* 127 */
  {0x000fffe6u, 20}, /* 128 */
  {0x003fffd2u, 22}, /* 129 */
  {0x000fffe7u, 20}, /* 130 */
  {0x000fffe8u, 20}, /* 131 */
  {0x003fffd3u, 22}, /* 132 */
  {0x003fffd4u, 22}, /* 133 */
  {0x003fffd5u, 22}, /* 134 */
  {0x007fffd9u, 23}, /* 135 */
  {0x003fffd6u, 22}, /* 136 */
  {0x007fffdau, 23}, /* 137 */
  {0x007fffdbu, 23}, /* 138 */
  {0x007fffdcu, 23}, /* 139 */
  {0x007fffddu, 23}, /* 140 */
  {0x007fffdeu, 23}, /* 141 */
  {0x00ffffebu, 24}, /* 142 */
  {0x007fffdfu, 23}, /* 143 */
  {0x00ffffecu, 24}, /* 144 */
  {0x00ffffedu, 24}, /* 145 */
  {0x003fffd7u, 22}, /* 146 */
  {0x007fffe0u, 23}, /* 147 */
  {0x00ffffeeu, 24}, /* 148 */
  {0x007fffe1u, 23}, /* 149 */
  {0x007fffe2u, 23}, /* 150 */
  {0x007fffe3u, 23}, /* 151 */
  {0x007fffe4u, 23}, /* 152 */
  {0x001fffdcu, 21}, /* 153 */
  {0x003fffd8u, 22}, /* 154 */
  {0x007fffe5u, 23}, /* 155 */
  {0x003fffd9u, 22}, /* 156 */
  {0x007fffe6u, 23}, /* 157 */
  {0x007fffe7u, 23}, /* 158 */
  {0x00ffffefu, 24}, /* 159 */
  {0x003fffdau, 22}, /* 160 */
  {0x001fffddu, 21}, /* 161 */
  {0x000fffe9u, 20}, /* 162 */
  {0x003fffdbu, 22}, /* 163 */
  {0x003fffdcu, 22}, /* 164 */
  {0x007fffe8u, 23}, /* 165 */
  {0x007fffe9u, 23}, /* 166 */
  {0x001fffdeu, 21}, /* 167 */
  {0x007fffeau, 23}, /* 168 */
  {0x003fffddu, 22}, /* 169 */
  {0x003fffdeu, 22}, /* 170 */
  {0x00fffff0u, 24}, /* 171 */
  {0x001fffdfu, 21}, /* 172 */
  {0x003fffdfu, 22}, /* 173 */
  {0x007fffebu, 23}, /* 174 */
  {0x007fffecu, 23}, /* 175 */
  {0x001fffe0u, 21}, /* 176 */
  {0x001fffe1u, 21}, /* 177 */
  {0x003fffe0u, 22}, /* 178 */
  {0x001fffe2u, 21}, /* 179 */
  {0x007fffedu, 23}, /* 180 */
  {0x003fffe1u, 22}, /* 181 */
  {0x007fffeeu, 23}, /* 182 */
  {0x007fffefu, 23}, /* 183 */
  {0x000fffeau, 20}, /* 184 */
  {0x003fffe2u, 22}, /* 185 */
  {0x003fffe3u, 22}, /* 186 */
  {0x003fffe4u, 22}, /* 187 */
  {0x007ffff0u, 23}, /* 188 */
  {0x003fffe5u, 22}, /* 189 */
  {0x003fffe6u, 22}, /* 190 */
  {0x007ffff1u, 23}, /* 191 */
  {0x03ffffe0u, 26}, /* 192 */
  {0x03ffffe1u, 26}, /* 193 */
  {0x000fffebu, 20}, /* 194 */
  {0x0007fff1u, 19}, /* 195 */
  {0x003fffe7u, 22}, /* 196 */
  {0x007ffff2u, 23}, /* 197 */
  {0x003fffe8u, 22}, /* 198 */
  {0x01ffffecu, 25}, /* 199 */
  {0x03ffffe2u, 26}, /* 200 */
  {0x03ffffe3u, 26}, /* 201 */
  {0x03ffffe4u, 26}, /* 202 */
  {0x07ffffdeu, 27}, /* 203 */
  {0x07ffffdfu, 27}, /* 204 */
  {0x03ffffe5u, 26}, /* 205 */
  {0x00fffff1u, 24}, /* 206 */
  {0x01ffffedu, 25}, /* 207 */
  {0x0007fff2u, 19}, /* 208 */
  {0x001fffe3u, 21}, /* 209 */
  {0x03ffffe6u, 26}, /* 210 */
  {0x07ffffe0u, 27}, /* 211 */
  {0x07ffffe1u, 27}, /* 212 */
  {0x03ffffe7u, 26}, /* 213 */
  {0x07ffffe2u, 27}, /* 214 */
  {0x00fffff2u, 24}, /* 215 */
  {0x001fffe4u, 21}, /* 216 */
  {0x001fffe5u, 21}, /* 217 */
  {0x03ffffe8u, 26}, /* 218 */
  {0x03ffffe9u, 26}, /* 219 */
  {0x0ffffffdu, 28}, /* 220 */
  {0x07ffffe3u, 27}, /* 221 */
  {0x07ffffe4u, 27}, /* 222 */
  {0x07ffffe5u, 27}, /* 223 */
  {0x000fffecu, 20}, /* 224 */
  {0x00fffff3u, 24}, /* 225 */
  {0x000fffedu, 20}, /* 226 */
  {0x001fffe6u, 21}, /* 227 */
  {0x003fffe9u, 22}, /* 228 */
  {0x001fffe7u, 21}, /* 229 */
  {0x001fffe8u, 21}, /* 230 */
  {0x007ffff3u, 23}, /* 231 */
  {0x003fffeau, 22}, /* 232 */
  {0x003fffebu, 22}, /* 233 */
  {0x01ffffeeu, 25}, /* 234 */
  {0x01ffffefu, 25}, /* 235 */
  {0x00fffff4u, 24}, /* 236 */
  {0x00fffff5u, 24}, /* 237 */
  {0x03ffffeau, 26}, /* 238 */
  {0x007ffff4u, 23}, /* 239 */
  {0x03ffffebu, 26}, /* 240 */
  {0x07ffffe6u, 27}, /* 241 */
  {0x03ffffecu, 26}, /* 242 */
  {0x03ffffedu, 26}, /* 243 */
  {0x07ffffe7u, 27}, /* 244 */
  {0x07ffffe8u, 27}, /* 245 */
  {0x07ffffe9u, 27}, /* 246 */
  {0x07ffffeau, 27}, /* 247 */
  {0x07ffffebu, 27}, /* 248 */
  {0x0ffffffeu, 28}, /* 249 */
  {0x07ffffecu, 27}, /* 250 */
  {0x07ffffedu, 27}, /* 251 */
  {0x07ffffeeu, 27}, /* 252 */
  {0x07ffffefu, 27}, /* 253 */
  {0x07fffff0u, 27}, /* 254 */
  {0x03ffffeeu, 26}, /* 255 */
  {0x3fffffffu, 30}, /* 256 */
};

/* ---------------------------------------------------------------- */
/* HPACK decoding (RFC 7541)                                         */
/* ---------------------------------------------------------------- */
typedef struct {
  char name[256];
  char val[4096];
} HPackEnt;

typedef struct {
  const unsigned char *p;
  const unsigned char *end;
} HPByte;

/* non-negative integer with an N-bit prefix in the low bits of the
   first octet (RFC 7541 5.1); advances *pp past the consumed octets */
static unsigned hpb_int(HPByte *b, int prefix)
{
  const unsigned char *p = b->p;
  if(p >= b->end)
    return 0;
  {
    unsigned mask = (1u << prefix) - 1;
    unsigned val = (unsigned)(*p & mask);
    p++;
    if(val < mask) {
      b->p = p;
      return val;
    }
    for(int k = 0; p < b->end; k++) {
      unsigned byte = *p++;
      val += (unsigned)((byte & 0x7fu) << (k * 7));
      if((byte & 0x80) == 0)
        break;
      if(k >= 5)
        break;
    }
    b->p = p;
    return val;
  }
}

static int huf_decode(const unsigned char *in, size_t inlen,
                      char *out, size_t cap);

/* read one HPACK string literal into out; returns length or -1 */
static int hp_str(HPByte *b, char *out, size_t cap)
{
  const unsigned char *p = b->p;
  int huff;
  size_t len;
  if(p >= b->end)
    return -1;
  huff = (int)(*p >> 7);
  {
    unsigned mask = 0x7f;
    len = (unsigned)(*p & mask);
    p++;
    if(len == 0x7f) {
      size_t extra = 0;
      for(int k = 0; p < b->end && k < 8; k++) {
        unsigned byte = *p++;
        extra += (size_t)((byte & 0x7fu) << (k * 7));
        if((byte & 0x80) == 0)
          break;
      }
      len = 0x7f + extra;
    }
  }
  if((size_t)(b->end - p) < len)
    return -1;
  if(!huff) {
    if(len + 1 > cap)
      return -1;
    memcpy(out, p, len);
    out[len] = 0;
    b->p = p + len;
    return (int)len;
  }
  {
    int n = huf_decode(p, len, out, cap);
    if(n < 0)
      return -1;
    b->p = p + len;
    return n;
  }
}

static int huf_decode(const unsigned char *in, size_t inlen,
                      char *out, size_t cap)
{
  unsigned long cur = 0;
  int nb = 0;
  size_t o = 0;
  for(size_t k = 0; k < inlen; k++) {
    cur = (cur << 8) | in[k];
    nb += 8;
    for(;;) {
      int sym = -1;
      for(int s = 0; s <= 256; s++) {
        int l = huf_code[s].len;
        unsigned long mask = (l >= 32) ? ~0ul : ((1ul << l) - 1);
        if(l && l <= nb &&
           ((((cur >> (nb - l)) & mask)) == huf_code[s].code)) {
          sym = s;
          break;
        }
      }
      if(sym < 0)
        break;
      if(sym == 256) {
        nb = 0;
        break;
      }
      if(o >= cap)
        return -1;
      out[o++] = (char)sym;
      nb -= huf_code[sym].len;
      if(nb > 63) {          /* unreachable in practice; guard */
        cur = 0;
        nb = 0;
      }
      else if(nb == 0)
        cur = 0;
      else
        cur &= (1ul << nb) - 1;
    }
  }
  out[o] = 0;
  return (int)o;
}

/* RFC 7541 Appendix A: static table */
static const char *hpack_static[61][2] = {
  {":authority", ""}, {":method", "GET"}, {":method", "POST"},
  {":path", "/"}, {":path", "/index.html"}, {":scheme", "http"},
  {":scheme", "https"}, {":status", "200"}, {":status", "204"},
  {":status", "206"}, {":status", "304"}, {":status", "400"},
  {":status", "404"}, {":status", "500"}, {"accept-charset", ""},
  {"accept-encoding", "gzip, deflate"}, {"accept-language", ""},
  {"accept-ranges", ""}, {"accept", ""},
  {"access-control-allow-origin", ""}, {"age", ""}, {"allow", ""},
  {"authorization", ""}, {"cache-control", ""},
  {"content-disposition", ""}, {"content-encoding", ""},
  {"content-language", ""}, {"content-length", ""},
  {"content-location", ""}, {"content-range", ""}, {"content-type", ""},
  {"cookie", ""}, {"date", ""}, {"etag", ""}, {"expect", ""},
  {"expires", ""}, {"from", ""}, {"host", ""}, {"if-match", ""},
  {"if-modified-since", ""}, {"if-none-match", ""}, {"if-range", ""},
  {"if-unmodified-since", ""}, {"last-modified", ""}, {"link", ""},
  {"location", ""}, {"max-forwards", ""}, {"proxy-authenticate", ""},
  {"proxy-authorization", ""}, {"range", ""}, {"referer", ""},
  {"refresh", ""}, {"retry-after", ""}, {"server", ""},
  {"set-cookie", ""}, {"strict-transport-security", ""},
  {"transfer-encoding", ""}, {"user-agent", ""}, {"vary", ""},
  {"via", ""}, {"www-authenticate", ""}
};

/* dynamic table (decode side); g_dyn[0] = newest */
static HPackEnt g_dyn[256];
static int g_ndyn = 0;
static size_t g_dynsz = 0;
static size_t g_dynmax = 4096;

static void g_dyn_add(const char *name, const char *val)
{
  size_t size = strlen(name) + strlen(val) + 32;
  if(size > g_dynmax)
    return;
  while(g_dynsz + size > g_dynmax && g_ndyn > 0) {
    g_ndyn--;
    g_dynsz -= strlen(g_dyn[g_ndyn].name) + strlen(g_dyn[g_ndyn].val) + 32;
  }
  if(g_ndyn >= 256)
    return;
  if(g_ndyn > 0)
    memmove(&g_dyn[1], &g_dyn[0], (size_t)g_ndyn * sizeof g_dyn[0]);
  snprintf(g_dyn[0].name, sizeof g_dyn[0].name, "%s", name);
  snprintf(g_dyn[0].val, sizeof g_dyn[0].val, "%s", val);
  g_ndyn++;
  g_dynsz += size;
}

static int hpack_lookup(unsigned idx, char *name, size_t nsz,
                        char *val, size_t vsz)
{
  if(idx >= 1 && idx <= 61) {
    snprintf(name, nsz, "%s", hpack_static[idx - 1][0]);
    snprintf(val, vsz, "%s", hpack_static[idx - 1][1]);
    return 0;
  }
  if(idx >= 62) {
    unsigned di = idx - 62;
    if(di < (unsigned)g_ndyn) {
      snprintf(name, nsz, "%s", g_dyn[di].name);
      snprintf(val, vsz, "%s", g_dyn[di].val);
      return 0;
    }
  }
  return -1;
}

/* decode a complete HPACK block into RespHeaders; returns 0 ok */
static int hpack_block(const unsigned char *data, size_t len, RespHeaders *h)
{
  HPByte b;
  char name[256], val[4096];
  unsigned byte = 0;
  b.p = data;
  b.end = data + len;
  while(b.p < b.end) {
    byte = *b.p;
    if(byte & 0x80) {
      unsigned idx = hpb_int(&b, 7);
      if(hpack_lookup(idx, name, sizeof name, val, sizeof val) != 0)
        goto bad;
    }
    else if((byte & 0xc0) == 0x40) {
      unsigned idx = hpb_int(&b, 6);
      if(idx == 0) {
        if(hp_str(&b, name, sizeof name) < 0)
          goto bad;
      }
      else if(hpack_lookup(idx, name, sizeof name, val, sizeof val) != 0)
        goto bad;
      if(hp_str(&b, val, sizeof val) < 0)
        goto bad;
      g_dyn_add(name, val);
    }
    else if((byte & 0xe0) == 0x20) {
      hpb_int(&b, 5);       /* dynamic table size update: ignored */
      continue;
    }
    else if((byte & 0xf0) == 0x10 ||
            (byte & 0xf0) == 0x00) {
      unsigned idx = hpb_int(&b, 4);
      if(idx == 0) {
        if(hp_str(&b, name, sizeof name) < 0)
          goto bad;
      }
      else if(hpack_lookup(idx, name, sizeof name, val, sizeof val) != 0)
        goto bad;
      if(hp_str(&b, val, sizeof val) < 0)
        goto bad;
    }
    else
      goto bad;
    if(h->n < VOLLEY_MAX_HDRS) {
      if(name[0] == ':') {
        if(!strcmp(name, ":status")) {
          h->code = atoi(val);
          snprintf(h->reason, sizeof h->reason, "OK");
        }
        continue;
      }
      snprintf(h->key[h->n], sizeof h->key[0], "%s", name);
      snprintf(h->val[h->n], sizeof h->val[0], "%s", val);
      if(!strcasecmp(name, "location"))
        snprintf(h->location, sizeof h->location, "%s", val);
      h->n++;
    }
  }
  return 0;
bad:
  fprintf(stderr, "h2: hpack decode failed (byte=0x%02x)\n", byte);
  return -1;
}

/* ---------------------------------------------------------------- */
/* HTTP/2 framing (RFC 7540)                                         */
/* ---------------------------------------------------------------- */
static int h2_write_frame(Conn *c, int type, int flags, unsigned stream,
                          const void *payload, size_t plen)
{
  unsigned char hdr[9];
  size_t chunk = 16384;
  const char *pp = (const char *)payload;
  size_t left = plen;
  hdr[0] = (unsigned char)((left >> 16) & 0xff);
  hdr[1] = (unsigned char)((left >> 8) & 0xff);
  hdr[2] = (unsigned char)(left & 0xff);
  hdr[3] = (unsigned char)type;
  hdr[4] = (unsigned char)flags;
  hdr[5] = (unsigned char)((stream >> 24) & 0x7f);
  hdr[6] = (unsigned char)((stream >> 16) & 0xff);
  hdr[7] = (unsigned char)((stream >> 8) & 0xff);
  hdr[8] = (unsigned char)(stream & 0xff);
  if(c_write_all(c, hdr, 9) != 0)
    return -1;
  if(getenv("H2ALL")) {
    FILE *f = fopen("/tmp/opencode/volley_all.bin", "ab");
    if(f) { fwrite(hdr,1,9,f); fclose(f); }
  }
  while(left) {
    size_t n = left > chunk ? chunk : left;
    if(c_write_all(c, pp, n) != 0)
      return -1;
    if(getenv("H2ALL")) {
      FILE *f = fopen("/tmp/opencode/volley_all.bin", "ab");
      if(f) { fwrite(pp,1,n,f); fclose(f); }
    }
    pp += n;
    left -= n;
  }
  return 0;
}

static int h2_read_frame(Conn *c, unsigned char *buf, size_t *plen,
                         int *type, int *flags, unsigned *stream)
{
  unsigned char hdr[9];
  size_t len;
  if(c_read(c, hdr, 9) != 9)
    return -1;
  len = ((size_t)hdr[0] << 16) | ((size_t)hdr[1] << 8) | hdr[2];
  *plen = len;
  *type = hdr[3];
  *flags = hdr[4];
  *stream = ((((unsigned)hdr[5]) & 0x7f) << 24) |
            ((unsigned)hdr[6] << 16) | ((unsigned)hdr[7] << 8) | hdr[8];
  if(len > (1u << 24))
    return -1;
  if(len && (c_read(c, buf, len) != (ssize_t)len))
    return -1;
  return 0;
}

/* ------------------------------------------------------------------ */
/* request side: small HPACK encoder for plain literals                */
/* ------------------------------------------------------------------ */
/* write a string literal with the hbit + length+payload */
static size_t h2_putstr(unsigned char *o, size_t cap, const char *s)
{
  size_t oi = 0;
  size_t vl = strlen(s);
  if(vl < 127) {
    if(oi < cap) o[oi++] = (unsigned char)vl;
  }
  else {
    if(oi < cap) o[oi++] = 0x7f;
    unsigned x = (unsigned)(vl - 127);
    while(x >= 128) {
      if(oi < cap) o[oi++] = (unsigned char)((x & 0x7f) | 0x80);
      x >>= 7;
    }
    if(oi < cap) o[oi++] = (unsigned char)x;
  }
  if(oi + vl <= cap) {
    memcpy(o + oi, s, vl);
    oi += vl;
  }
  return oi;
}

/* literal without indexing: 4-bit prefix, name via static index if known */
static size_t h2_hpack_field(unsigned char *out, size_t cap,
                             const char *name, const char *val)
{
  size_t oi = 0;
  int idx = 0;
  for(int i = 0; i < 61; i++)
    if(!strcasecmp(hpack_static[i][0], name) &&
       !strcmp(hpack_static[i][1], val) && hpack_static[i][1][0]) {
      idx = i + 1;
      break;
    }
  if(idx) {
    out[oi++] = (unsigned char)((idx < 127 ? idx : 0x7f) | 0x80);
    if(idx >= 127) {
      unsigned x = (unsigned)(idx - 127);
      while(x >= 128) {
        if(oi < cap) out[oi++] = (unsigned char)((x & 0x7f) | 0x80);
        x >>= 7;
      }
      if(oi < cap) out[oi++] = (unsigned char)x;
    }
    return oi;
  }
  idx = 0;
  for(int i = 0; i < 61; i++)
    if(!strcasecmp(hpack_static[i][0], name)) {
      idx = i + 1;
      break;
    }
  if(idx) {
    out[oi++] = (unsigned char)(idx < 15 ? idx : 0x0f);
    if(idx >= 15) {
      unsigned x = (unsigned)(idx - 15);
      while(x >= 128) {
        if(oi < cap) out[oi++] = (unsigned char)((x & 0x7f) | 0x80);
        x >>= 7;
      }
      if(oi < cap) out[oi++] = (unsigned char)x;
    }
  }
  else {
    if(oi < cap) out[oi++] = 0;
    oi += h2_putstr(out + oi, cap - oi, name);
  }
  oi += h2_putstr(out + oi, cap - oi, val);
  return oi;
}

/* build the request HEADERS block (lower-cased extra headers) */
static size_t h2_build_request(unsigned char *out, size_t cap, Req *r)
{
  static const char *excl[] = {
    "host", "authority", "user-agent", "accept", "accept-encoding",
    "content-length", "connection", "transfer-encoding", "proxy-connection",
    "upgrade", "http2-settings", "te"
  };
  char hp2[640];
  size_t oi = 0;

  oi += h2_hpack_field(out + oi, cap - oi, ":method", r->method);
  oi += h2_hpack_field(out + oi, cap - oi, ":scheme",
                       r->https ? "https" : "http");
  oi += h2_hpack_field(out + oi, cap - oi, ":path", r->path);
  host_header(hp2, sizeof hp2, r->host, r->port, r->https);
  oi += h2_hpack_field(out + oi, cap - oi, ":authority", hp2);
  oi += h2_hpack_field(out + oi, cap - oi, "user-agent",
                       r->useragent ? r->useragent : "curl/8.5.0");
  oi += h2_hpack_field(out + oi, cap - oi, "accept", "*/*");
  oi += h2_hpack_field(out + oi, cap - oi, "accept-encoding", "identity");
  snprintf(hp2, sizeof hp2, "%llu", (unsigned long long)r->body_len);
  if((r->body && r->body_len)) {
    oi += h2_hpack_field(out + oi, cap - oi, "content-length", hp2);
    if(r->content_type && r->content_type[0])
      oi += h2_hpack_field(out + oi, cap - oi, "content-type", r->content_type);
  }
  if(r->range && r->range[0])
    oi += h2_hpack_field(out + oi, cap - oi, "range", r->range);
  if(r->cookie && r->cookie[0])
    oi += h2_hpack_field(out + oi, cap - oi, "cookie", r->cookie);
  if(r->auth && r->auth[0])
    oi += h2_hpack_field(out + oi, cap - oi, "authorization", r->auth);
  for(int hx = 0; hx < r->nuhdrs; hx++) {
    char *colon = strchr(r->uhdrs[hx], ':');
    if(!colon)
      continue;
    char lower[256], vv[1024];
    size_t nl = (size_t)(colon - r->uhdrs[hx]);
    if(nl >= sizeof lower)
      nl = sizeof lower - 1;
    memcpy(lower, r->uhdrs[hx], nl);
    lower[nl] = 0;
    for(char *q = lower; *q; q++)
      *q = (char)tolower((unsigned char)*q);
    int skip = 0;
    for(size_t xk = 0; xk < sizeof excl / sizeof excl[0]; xk++)
      if(!strcmp(lower, excl[xk])) {
        skip = 1;
        break;
      }
    if(skip)
      continue;
    const char *vvp = colon + 1;
    while(*vvp == ' ')
      vvp++;
    snprintf(vv, sizeof vv, "%s", vvp);
    size_t add = h2_hpack_field(out + oi, cap - oi, lower, vv);
    oi += add;
  }
  return oi;
}

/* ------------------------------------------------------------------ */
/* deliver a fully-buffered h2 body through the normal emit pipeline   */
/* (decode + stream to file or buffer for later render/print)          */
/* ------------------------------------------------------------------ */
static long long consume_h2_body(RespHeaders *h, XOpt *xo, Res *res,
                                 Buffer *src)
{
  double t0 = now_ms();
  int do_stream = xo->stream_to != NULL;
  FILE *fp = xo->stream_to;
  Buffer mb;
  long long done = 0;
  int fail = 0;
  CDec dec;

  if(*h->content_encoding && !xo->no_decode) {
    if(dec_start(&dec, h->content_encoding) != 0) {
      snprintf(res->err, sizeof res->err, "failed to init decoder");
      return -1;
    }
  }
  else
    memset(&dec, 0, sizeof dec);
  memset(&mb, 0, sizeof mb);

  if(src->data && src->len) {
    const char *p = src->data;
    size_t left = src->len;
    while(left) {
      size_t n = left > VOLLEY_IO ? VOLLEY_IO : left;
      rate_pace((long long)n);
      {
        int cc = dec_push(&dec, p, n, do_stream, fp, &mb, &done, t0);
        if(cc == -2) {
          snprintf(res->err, sizeof res->err, "content decoding failed (%s)",
                   h->content_encoding);
          fail = 1;
          break;
        }
        if(cc != 0) {
          snprintf(res->err, sizeof res->err, "failed writing output");
          fail = 1;
          break;
        }
      }
      p += n;
      left -= n;
    }
    if(!fail) {
      int df = dec_finish(&dec, do_stream, fp, &mb, &done, t0);
      if(df == -2) {
        snprintf(res->err, sizeof res->err, "content decoding failed (%s)",
                 h->content_encoding);
        fail = 1;
      }
      else if(df != 0) {
        snprintf(res->err, sizeof res->err, "failed writing output");
        fail = 1;
      }
    }
  }
  dec_fin(&dec);
  res->body = mb;
  return fail ? -1 : done;
}

/* ------------------------------------------------------------------ */
/* the actual HTTP/2 request/response cycle on an established TLS conn */
/* ------------------------------------------------------------------ */
static int h2_transfer(Conn *c, Req *rq, RespHeaders *h, Buffer *body,
                       char *err, size_t ersz)
{
  unsigned char hdr[16384];
  size_t hlen;
  unsigned sid = 1;
  long long flow = 0;
  int got_eos = 0;

  g_ndyn = 0;
  g_dynsz = 0;
  memset(h, 0, sizeof *h);
  memset(body, 0, sizeof *body);

  if(c_write_all(c, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) != 0)
    return -1;
  if(h2_write_frame(c, 4, 0, 0, NULL, 0) != 0)
    return -1;

  hlen = h2_build_request(hdr, sizeof hdr, rq);
  {
    int flags = 0x4;                    /* END_HEADERS */
    if(!(rq->body && rq->body_len))
      flags |= 0x1;                     /* END_STREAM */
    if(h2_write_frame(c, 1, flags, sid, hdr, hlen) != 0)
      return -1;
    if(getenv("H2RAW")) {
      fputs("H2RAW req: ", stderr);
      for(size_t i = 0; i < hlen; i++)
        fprintf(stderr, "%02x", hdr[i]);
      fputc('\n', stderr);
    }
    if(getenv("H2DBG")) {
      fprintf(stderr, "h2dbg: HEADERS len=%zu hex:", hlen);
      for(size_t i = 0; i < hlen; i++)
        fprintf(stderr, "%02x", hdr[i]);
      fprintf(stderr, "\n");
    }
  }
  if(rq->body && rq->body_len) {
    size_t off = 0;
    while(off < rq->body_len) {
      size_t n = rq->body_len - off;
      int fl = 0;
      if(n > 16384)
        n = 16384;
      if(off + n >= rq->body_len)
        fl = 0x1;
      if(h2_write_frame(c, 0, fl, sid, rq->body + off, n) != 0)
        return -1;
      off += n;
    }
  }

  for(;;) {
    unsigned char fbuf[65536];
    size_t plen;
    int type, flags;
    unsigned stream;
    if(h2_read_frame(c, fbuf, &plen, &type, &flags, &stream) != 0) {
      if(getenv("H2DBG"))
        fprintf(stderr, "h2dbg: read failed\n");
      if(getenv("H2RAW")) {
    fprintf(stderr, "H2RAW req hex: ");
    for(size_t qi = 0; qi < hlen; qi++)
      fprintf(stderr, "%02x", hdr[qi]);
    fprintf(stderr, " len=%zu\n", hlen);
  }
  snprintf(err, ersz, "h2: connection dropped");
      return -1;
    }
    if(getenv("H2DBG"))
      fprintf(stderr, "h2dbg: frame type=%d flags=%d len=%zu stream=%u\n",
              type, flags, plen, stream);
    switch(type) {
    case 0:   /* DATA */
      if(flags & 0x1)
        got_eos = 1;
      if(stream == sid && plen) {
        if(b_add(body, (const char *)fbuf, plen) != 0) {
          snprintf(err, ersz, "h2: out of memory");
          return -1;
        }
        flow += (long long)plen;
        if(flow >= 32768) {
          unsigned inc = (unsigned)flow;
          unsigned char wu[4] = {
            (unsigned char)(inc >> 24), (unsigned char)(inc >> 16),
            (unsigned char)(inc >> 8), (unsigned char)inc
          };
          h2_write_frame(c, 8, 0, 0, wu, 4);
          h2_write_frame(c, 8, 0, sid, wu, 4);
          flow = 0;
        }
      }
      if(stream == sid)
        got_eos = got_eos;
      break;
    case 1:   /* HEADERS */
      if(flags & 0x1)
        got_eos = 1;
      {
        /* accumulate header-block fragments (HEADERS + CONTINUATION) */
        unsigned char *acc = NULL;
        size_t accn = 0, acccap = 0;
        int first = 1;
        for(;;) {
          const unsigned char *frag = fbuf;
          size_t flen = plen;
          size_t pad = 0;
          if(first) {
            if(flags & 0x8) {              /* PADDED: drop pad-length byte */
              if(flen < 1) {
                free(acc);
                snprintf(err, ersz, "h2: malformed padded headers");
                return -1;
              }
              pad = fbuf[0];
              frag = fbuf + 1;
              flen -= 1;
              if(pad > flen) {
                free(acc);
                snprintf(err, ersz, "h2: malformed pad length");
                return -1;
              }
            }
            if(flags & 0x20) {             /* PRIORITY: drop 5 bytes */
              if(flen < 5) {
                free(acc);
                snprintf(err, ersz, "h2: malformed priority headers");
                return -1;
              }
              frag += 5;
              flen -= 5;
            }
            if(pad) {
              if(pad > flen)
                pad = flen;
              flen -= pad;
            }
            first = 0;
          }
          if(flen) {
            if(accn + flen > acccap) {
              size_t nc = acccap ? acccap * 2 : 4096;
              while(nc < accn + flen)
                nc *= 2;
              {
                unsigned char *nu = realloc(acc, nc);
                if(!nu) {
                  free(acc);
                  snprintf(err, ersz, "h2: out of memory");
                  return -1;
                }
                acc = nu;
                acccap = nc;
              }
            }
            memcpy(acc + accn, frag, flen);
            accn += flen;
          }
          if(flags & 0x4)                  /* END_HEADERS */
            break;
          if(h2_read_frame(c, fbuf, &plen, &type, &flags, &stream) != 0) {
            free(acc);
            snprintf(err, ersz, "h2: continuation dropped");
            return -1;
          }
          if(type != 9) {
            free(acc);
            snprintf(err, ersz, "h2: expected CONTINUATION");
            return -1;
          }
        }
        if(hpack_block(acc, accn, h) != 0) {
          free(acc);
          snprintf(err, ersz, "h2: hpack decode failed");
          return -1;
        }
        free(acc);
      }
      break;
    case 4:   /* SETTINGS */
      if(!(flags & 0x1))
        h2_write_frame(c, 4, 0x1, 0, NULL, 0);
      break;
    case 6:   /* PING */
      if(!(flags & 0x1))
        h2_write_frame(c, 6, 0x1, stream, fbuf, plen);
      break;
    case 3:   /* RST_STREAM */
    case 7:   /* GOAWAY */
      snprintf(err, ersz, "h2: stream %s by server",
               type == 3 ? "reset" : "goaway");
      return -1;
    case 8:   /* WINDOW_UPDATE */
    case 5:   /* PUSH_PROMISE */
    default:
      break;
    }
    if(got_eos && h->code != 0) {
      break;
    }
  }
  return 0;
}
/* ---------------------------------------------------------------- */
/* the real worker: follow redirects, stream or buffer the body      */
/* ---------------------------------------------------------------- */
static void do_transfer(Cfg *cfg, Jb *jb, Res *res, XOpt *xo)
{
  double t0 = now_ms();
  char url[2048];
  Url u = jb->u;
  int redirs = 0;

  memset(res, 0, sizeof *res);
  res->bytes = -1;
  res->total = -1;
  snprintf(url, sizeof url, "%s", jb->url);
  snprintf(res->final_url, sizeof res->final_url, "%s", jb->url);

  if(cfg->nurls == 1 && g_verbose)
    fprintf(stderr, "%svolley> %s %s%s\n", CD, cfg->head ? "HEAD" : cfg->method,
            jb->url, CK);

  for(;;) {
    Conn *c;
    Req rq;
    BR br;
    RespHeaders h;
    int e;
    int skip_body;
    long long nb;
    int keep;
    int h2used = 0;
    Buffer h2b;

    if(redirs >= VOLLEY_MAX_REDIRS) {
      snprintf(res->err, sizeof res->err, "too many redirects");
      return;
    }

    c = pool_get(u.host, u.port, u.https, cfg->insecure);
    if(!c) {
      snprintf(res->err, sizeof res->err, "failed to connect to %s:%s",
               u.host, u.port);
      return;
    }

    memset(&h2b, 0, sizeof h2b);
    memset(&rq, 0, sizeof rq);
    rq.method = cfg->head ? "HEAD" : cfg->method;
    rq.path = u.path;
    rq.host = u.host;
    rq.port = u.port;
    rq.https = u.https;
    rq.range = (xo && xo->range) ? xo->range : cfg->range;
    rq.useragent = cfg->useragent;
    rq.body = cfg->body;
    rq.body_len = cfg->body_len;
    rq.content_type = cfg->ctype;
    rq.uhdrs = cfg->uhdrs;
    rq.nuhdrs = cfg->nuhdrs;
    rq.abs_url = (g_proxy.type == 1 && !u.https);
    if((g_cook_use || g_sess_active) && g_cook_enabled)
      rq.cookie = cookie_header(u.host, u.path, u.https);
    else
      rq.cookie = NULL;
    rq.chunked = cfg->chunked;
    rq.up_file = cfg->up_file;
    {
      char auth[512] = "";
      resolve_auth(cfg, &u, auth, sizeof auth);
      rq.auth = auth;
    }

    /* ------------------------------------------------------------------ */
    /* HTTP/2 path (opt-in via --http2, direct https only)                */
    /* ------------------------------------------------------------------ */
    if(g_http2 && u.https && g_proxy.type == 0 && c->alpn == 1) {
      memset(&h, 0, sizeof h);
      if(h2_transfer(c, &rq, &h, &h2b, res->err, sizeof res->err) != 0) {
        pool_put(c, 0);
        if(!res->err[0])
          snprintf(res->err, sizeof res->err, "http/2 request failed");
        return;
      }
      h2used = 1;
    }
    else if(send_req(c, &rq) != 0) {
      pool_put(c, 0);
      snprintf(res->err, sizeof res->err, "failed to send request to %s",
               u.host);
      return;
    }
    else {
      memset(&br, 0, sizeof br);
      br.c = c;
      e = read_headers(&br, &h);
      if(e != 0) {
        pool_put(c, 0);
        snprintf(res->err, sizeof res->err, "%s",
                 e == -2 ? "timed out waiting for response"
                         : "connection closed before response");
        return;
      }
    }

    res->status = h.code;
    res->http_err = h.code >= 400;
    if((g_cook_use || g_sess_active) && g_cook_enabled) {
      for(int hn = 0; hn < h.n; hn++)
        if(!strcasecmp(h.key[hn], "set-cookie"))
          cookie_handle_set(u.host, u.path, h.val[hn]);
    }
    if(h.content_range[0]) {
      const char *cr = h.content_range;
      const char *d0 = cr;
      if(!strncmp(d0, "bytes ", 6))
        d0 += 6;
      res->cr_first = atoll(d0);
      res->cr_last = -1;
      {
        const char *dash = strchr(d0, '-');
        if(dash)
          res->cr_last = atoll(dash + 1);
      }
      {
        const char *sl = strrchr(h.content_range, '/');
        res->total = (sl && sl[1] != '*') ? atoll(sl + 1) : -1;
      }
      res->cr_ok = (res->cr_first >= 0 && res->cr_last >= res->cr_first);
    }
    else if(h.has_clen)
      res->total = h.clen;
    snprintf(res->final_url, sizeof res->final_url, "%s", url);

    if(cfg->include_hdrs) {
      pthread_mutex_lock(&g_omu);
      if(h.version[0])
        fprintf(stdout, "HTTP/%s %d %s\r\n", h.version, h.code,
                h.reason[0] ? h.reason : "");
      else
        fprintf(stdout, "HTTP/2 %d %s\r\n", h.code,
                h.reason[0] ? h.reason : "");
      for(int i = 0; i < h.n; i++)
        fprintf(stdout, "%s: %s\r\n", h.key[i], h.val[i]);
      fputs("\r\n", stdout);
      fflush(stdout);
      pthread_mutex_unlock(&g_omu);
    }

    /* redirect? */
    if(cfg->follow && h.code >= 300 && h.code < 400 && h.code != 304 &&
       h.location[0]) {
      Url nu;
      char newurl[2048];
      resolve_url(url, h.location, newurl, sizeof newurl);
      pool_put(c, 0);
      free(h2b.data);
      h2b.data = NULL;
      if(parse_url(newurl, &nu) != 0) {
        snprintf(res->err, sizeof res->err, "bad redirect location: %s",
                 h.location);
        return;
      }
      u = nu;
      snprintf(url, sizeof url, "%s", newurl);
      redirs++;
      if(g_verbose)
        fprintf(stderr, "%svolley> redirect -> %s%s\n", CD, newurl, CK);
      continue;
    }

    skip_body = cfg->head || h.code == 204 || h.code == 304 ||
                (h.code >= 100 && h.code < 200);
    if(skip_body) {
      nb = 0;
      res->net_ok = 1;
    }
    else if(h2used) {
      nb = consume_h2_body(&h, xo, res, &h2b);
      free(h2b.data);
      h2b.data = NULL;
      if(nb < 0)
        pool_put(c, 0);
      else
        res->net_ok = 1;
    }
    else {
      nb = read_body(&br, &h, xo, res);
      if(nb < 0)
        pool_put(c, 0);
      else
        res->net_ok = 1;
    }

    res->bytes = nb;
    res->ms = now_ms() - t0;
    if(!res->net_ok && !res->err[0])
      snprintf(res->err, sizeof res->err, "transfer incomplete");
    if(res->err[0])
      strncpy(g_lasterr, res->err, sizeof g_lasterr - 1);
    else
      g_lasterr[0] = 0;

    keep = (res->net_ok && !h.conn_close && !h2used);
    pool_put(c, keep ? 1 : 0);
    return;
  }
}

/* ---------------------------------------------------------------- */
/* segmented (parallel-range) download                               */
/* ---------------------------------------------------------------- */
typedef struct {
  Cfg *cfg;
  Jb *jb;
  long long start, end;
  char rng[96];
  char *data;
  long long len;
  int ok;
  char err[512];
} Seg;

static void *seg_worker(void *arg)
{
  Seg *s = arg;
  XOpt xo;
  Res res;

  memset(&xo, 0, sizeof xo);
  xo.range = s->rng;
  xo.no_decode = s->cfg->no_decode;
  memset(&res, 0, sizeof res);
  res.bytes = -1;
  res.total = -1;

  do_transfer(s->cfg, s->jb, &res, &xo);
  if(res.net_ok && res.status == 206 && res.body.len) {
    s->data = res.body.data;
    s->len = (long long)res.body.len;
    s->ok = 1;
  }
  else {
    if(res.err[0])
      snprintf(s->err, sizeof s->err, "%s", res.err);
    else
      snprintf(s->err, sizeof s->err, "segment %lld-%lld failed (status %d)",
               s->start, s->end, res.status);
    free(res.body.data);
  }
  return NULL;
}

/* returns 0 ok, 2 = server has no range support (fall back) */
static int segmented_download(Cfg *cfg, Jb *jb, Res *res)
{
  XOpt xo;
  Res probe;
  long long total;
  int nsegs, i;
  Seg *segs;
  pthread_t *ths;
  double t0 = now_ms();
  FILE *ff;
  int bad = 0;

  memset(&xo, 0, sizeof xo);
  xo.range = "0-0";
  memset(&probe, 0, sizeof probe);
  probe.bytes = -1;
  probe.total = -1;

  do_transfer(cfg, jb, &probe, &xo);
  if(!probe.net_ok || probe.status != 206)
    return 2;
  total = probe.total;
  free(probe.body.data);
  if(total <= 1)
    return 2;

  nsegs = cfg->segs;
  if(nsegs < 1)
    nsegs = 1;
  if(nsegs > VOLLEY_MAX_SEGS)
    nsegs = VOLLEY_MAX_SEGS;
  if(nsegs > total)
    nsegs = (int)total;
  if(total < 65536)
    nsegs = 1;

  segs = calloc((size_t)nsegs, sizeof(Seg));
  ths = malloc((size_t)nsegs * sizeof(pthread_t));
  if(!segs || !ths) {
    free(segs);
    free(ths);
    snprintf(res->err, sizeof res->err, "out of memory");
    return -1;
  }

  for(i = 0; i < nsegs; i++) {
    segs[i].cfg = cfg;
    segs[i].jb = jb;
    segs[i].start = total * i / nsegs;
    segs[i].end = total * (i + 1) / nsegs - 1;
    snprintf(segs[i].rng, sizeof segs[i].rng, "%lld-%lld",
             segs[i].start, segs[i].end);
  }

  for(i = 0; i < nsegs; i++)
    pthread_create(&ths[i], NULL, seg_worker, &segs[i]);
  for(i = 0; i < nsegs; i++)
    pthread_join(ths[i], NULL);

  ff = fopen(jb->save_path, "wb");
  if(!ff) {
    snprintf(res->err, sizeof res->err, "can't open %s: %s",
             jb->save_path, strerror(errno));
    for(i = 0; i < nsegs; i++)
      free(segs[i].data);
    free(segs);
    free(ths);
    return -1;
  }
  for(i = 0; i < nsegs; i++) {
    if(segs[i].ok)
      fwrite(segs[i].data, 1, (size_t)segs[i].len, ff);
    else
      bad = 1;
  }
  fclose(ff);
  for(i = 0; i < nsegs; i++)
    free(segs[i].data);

  if(bad) {
    snprintf(res->err, sizeof res->err, "some segments failed (partial file)");
    res->net_ok = 0;
    res->status = 0;
    free(segs);
    free(ths);
    return -1;
  }

  if(!cfg->silent)
    fprintf(stderr, "%s%s%d%s %s %d segments in %.2fs -> %s%s\n",
            CD, status_color(206), 206, CK, CD, nsegs, now_ms() - t0,
            jb->save_path, CK);

  res->status = 206;
  res->bytes = total;
  res->total = total;
  res->ms = now_ms() - t0;
  res->net_ok = 1;
  res->streamed = 1;

  free(segs);
  free(ths);
  return 0;
}

/* ---------------------------------------------------------------- */
/* single job runner                                                 */
/* ---------------------------------------------------------------- */
static void run_job(Cfg *cfg, Jb *jb, Res *res)
{
  XOpt xo;
  FILE *fp = NULL;
  int stream, g_was;

  memset(res, 0, sizeof *res);
  res->bytes = -1;
  res->total = -1;

  if(jb->u.proto == 1) {
    do_ftp(cfg, jb, res, g_upload_file ? "STOR" : "RETR",
           g_listonly ? "NLST" : "LIST");
    return;
  }
  if(jb->u.proto == 2) {
    do_gopher(cfg, jb, res);
    return;
  }

  if(cfg->segs > 1 && cfg->nurls == 1 && jb->save_path[0]) {
    int r2 = segmented_download(cfg, jb, res);
    if(r2 != 2)
      return;
    memset(res, 0, sizeof *res);
    res->bytes = -1;
    res->total = -1;
  }

  memset(&xo, 0, sizeof xo);
  xo.range = cfg->range;
  xo.no_decode = cfg->no_decode;
  stream = (cfg->nurls == 1 && cfg->segs <= 1 && jb->save_path[0]);
  g_was = g_prog;
  if(stream) {
    char resrange[64] = "";
    if(cfg->resume_str && !cfg->range) {
      long long off = 0;
      if(!strcmp(cfg->resume_str, "-")) {
        struct stat st;
        if(stat(jb->save_path, &st) == 0)
          off = (long long)st.st_size;
      }
      else
        off = cfg->resume_off;
      if(off > 0) {
        snprintf(resrange, sizeof resrange, "%lld-", off);
        xo.range = resrange;
        fp = fopen(jb->save_path, "ab");
      }
    }
    if(!fp)
      fp = fopen(jb->save_path, "wb");
    if(!fp) {
      snprintf(res->err, sizeof res->err, "can't open %s: %s",
               jb->save_path, strerror(errno));
      return;
    }
    xo.stream_to = fp;
    if(!cfg->silent && isatty(2))
      g_prog = 1;
  }
  rate_init();
  do_transfer(cfg, jb, res, &xo);

  if(fp) {
    fclose(fp);
    res->streamed = 1;
  }
  if(g_prog && !g_was) {
    g_prog = 0;
    prog_end();
    fputs("\n", stderr);
  }
  g_prog = g_was;
}

/* ---------------------------------------------------------------- */
/* writing buffered results and the summary line                     */
/* ---------------------------------------------------------------- */
static void git_char_to_utf8(Buffer *o, unsigned long v)
{
  unsigned char b[4];
  if(v < 0x80)      { b[0] = (unsigned char)v;                 b_add(o, (const char *)b, 1); }
  else if(v < 0x800) { b[0] = 0xC0 | (v >> 6);  b[1] = 0x80 | (v & 0x3F);
                       b_add(o, (const char *)b, 2); }
  else if(v < 0x10000) { b[0] = 0xE0 | (v >> 12); b[1] = 0x80 | ((v >> 6) & 0x3F);
                       b[2] = 0x80 | (v & 0x3F); b_add(o, (const char *)b, 3); }
  else              { b[0] = 0xF0 | (v >> 18); b[1] = 0x80 | ((v >> 12) & 0x3F);
                       b[2] = 0x80 | ((v >> 6) & 0x3F); b[3] = 0x80 | (v & 0x3F);
                       b_add(o, (const char *)b, 4); }
}

static void html_add_entity(Buffer *o,
                            const unsigned char *p, const unsigned char *end,
                            const unsigned char **next)
{
  const unsigned char *q = p + 1;
  if(q < end && *q == '#') {
    const unsigned char *r = q + 1;
    unsigned long v = 0;
    int base = 10, any = 0;
    if(r < end && (*r == 'x' || *r == 'X')) { base = 16; r++; }
    while(r < end && *r != ';' && (size_t)(r - q) < 12) {
      char c = (char)*r;
      int d = -1;
      if(c >= '0' && c <= '9') d = c - '0';
      else if(base == 16 && c >= 'a' && c <= 'f') d = c - 'a' + 10;
      else if(base == 16 && c >= 'A' && c <= 'F') d = c - 'A' + 10;
      if(d < 0) break;
      v = v * (unsigned long)base + (unsigned long)d;
      any = 1;
      r++;
    }
    if(any && r < end && *r == ';') {
      *next = r + 1;
      if(v == 0xA0 || v == 0x20)
        b_add(o, " ", 1);
      else if(v < 0x20 || v == 0x7F)
        b_add(o, " ", 1);
      else
        git_char_to_utf8(o, v);
      return;
    }
  }
  else {
    static const struct { const char *n; const char *utf8; }
    ents[] = {
      {"amp", "&"}, {"lt", "<"}, {"gt", ">"},
      {"quot", "\""}, {"apos", "'"}, {"nbsp", " "},
      {"mdash", "\342\200\224"}, {"ndash", "\342\200\223"},
      {"hellip", "\342\200\246"}, {"lsquo", "\342\200\230"},
      {"rsquo", "\342\200\231"}, {"ldquo", "\342\200\234"},
      {"rdquo", "\342\200\235"}, {"bull", "\342\200\242"},
      {"copy", "\302\251"}, {"reg", "\302\256"},
      {"laquo", "\302\253"}, {"raquo", "\302\273"},
      {NULL, NULL}
    };
    for(int i = 0; ents[i].n; i++) {
      size_t nl = strlen(ents[i].n);
      if((size_t)(end - (p + 1)) > nl && !memcmp(p + 1, ents[i].n, nl) &&
         p[1 + nl] == ';') {
        b_add(o, ents[i].utf8, strlen(ents[i].utf8));
        *next = p + 1 + nl + 1;
        return;
      }
    }
  }
  b_add(o, "&", 1);
  *next = p + 1;
}

static const unsigned char *git_find_ci(const unsigned char *h, size_t n,
                                        const char *needle)
{
  size_t nl = strlen(needle);
  if(n < nl)
    return NULL;
  for(size_t i = 0; i + nl <= n; i++) {
    size_t k;
    for(k = 0; k < nl; k++) {
      unsigned char a = h[i + k], b2 = (unsigned char)needle[k];
      if(tolower((int)a) != tolower((int)b2))
        break;
    }
    if(k == nl)
      return h + i;
  }
  return NULL;
}

/* render an HTML body to plain text (script/style stripped, block tags
   become lines, entities decoded, <pre> kept verbatim)                 */
static void html_to_text(const unsigned char *b, size_t n, Buffer *o)
{
  const unsigned char *p = b, *end = b + n;
  int pre = 0, lastw = 1;
  while(p < end) {
    unsigned char c = *p;
    if(c != '<') {
      if(c == '&') {
        const unsigned char *nx;
        html_add_entity(o, p, end, &nx);
        if(nx > p) { lastw = 0; p = nx; continue; }
      }
      if(pre) {
        b_add(o, (const char *)&c, 1);
        if(c == '\n' || c == '\t') lastw = 0;
        else if(!isspace(c)) lastw = 0;
      }
      else if(isspace(c)) {
        if(!lastw) {
          b_add(o, " ", 1);
          lastw = 1;
        }
      }
      else {
        b_add(o, (const char *)&c, 1);
        lastw = 0;
      }
      p++;
      continue;
    }
    if(pre) {
      const unsigned char *cl = git_find_ci(p, (size_t)(end - p), "</pre");
      if(!cl) {
        b_add(o, "<", 1);
        p++;
        continue;
      }
      const unsigned char *gt = cl;
      while(gt < end && *gt != '>') gt++;
      p = gt < end ? gt + 1 : end;
      pre = 0;
      continue;
    }
    if((size_t)(end - p) >= 4 && !memcmp(p, "<!--", 4)) {
      const unsigned char *q = p + 4;
      while(q + 2 < end && !(q[0] == '-' && q[1] == '-' && q[2] == '>'))
        q++;
      p = q + 2 < end ? q + 3 : end;
      continue;
    }
    {
      const unsigned char *t = p + 1;
      size_t tn = 0;
      char tnm[24];
      while(t < end && tn < sizeof tnm - 1 && *t != '>' &&
            !isspace(*t) && *t != '/') {
        tnm[tn++] = (char)tolower((int)*t);
        t++;
      }
      tnm[tn] = 0;
      {
        const unsigned char *gt = t;
        while(gt < end && *gt != '>')
          gt++;
        if(gt >= end) {
          b_add(o, "<", 1);
          lastw = 0;
          p++;
          continue;
        }
        const unsigned char *ts = p;
        p = gt + 1;
        if(!strcmp(tnm, "script") || !strcmp(tnm, "style")) {
          const char *endtag = !strcmp(tnm, "script") ? "</script" : "</style";
          const unsigned char *cl = git_find_ci(p, (size_t)(end - p), endtag);
          if(cl) {
            const unsigned char *ce = cl;
            while(ce < end && *ce != '>') ce++;
            p = ce < end ? ce + 1 : end;
          }
          continue;
        }
        if(!strcmp(tnm, "pre"))
          pre = 1;
        else if(!strcmp(tnm, "br") || !strcmp(tnm, "hr")) {
          if(!lastw) {
            b_add(o, "\n", 1);
            lastw = 1;
          }
        }
        else if(tnm[0] == 'h' && tnm[1] >= '1' && tnm[1] <= '6' &&
                tnm[2] == 0) {
          if(!lastw) {
            b_add(o, "\n", 1);
            lastw = 1;
          }
        }
        else if(tnm[0] == 'h' && tnm[1] == 'e' && !strcmp(tnm, "head")) {
          b_add(o, "\n", 1);
          lastw = 1;
        }
        else if(!strcmp(tnm, "p") || !strcmp(tnm, "div") ||
                !strcmp(tnm, "section") || !strcmp(tnm, "article") ||
                !strcmp(tnm, "header") || !strcmp(tnm, "footer") ||
                !strcmp(tnm, "main") || !strcmp(tnm, "aside") ||
                !strcmp(tnm, "nav") || !strcmp(tnm, "ul") ||
                !strcmp(tnm, "ol") || !strcmp(tnm, "li") ||
                !strcmp(tnm, "table") || !strcmp(tnm, "tr") ||
                !strcmp(tnm, "blockquote") || !strcmp(tnm, "address") ||
                !strcmp(tnm, "figure") || !strcmp(tnm, "figcaption") ||
                !strcmp(tnm, "fieldset") || !strcmp(tnm, "legend") ||
                !strcmp(tnm, "details") || !strcmp(tnm, "summary")) {
          if(!lastw) {
            b_add(o, "\n", 1);
            lastw = 1;
          }
        }
        else if(!strcmp(tnm, "td") || !strcmp(tnm, "th")) {
          if(!lastw) {
            b_add(o, "  ", 2);
            lastw = 1;
          }
        }
        else if(!strcmp(tnm, "img")) {
          const unsigned char *al = ts + 1;
          while(al + 4 < gt && strncmp((const char *)al, "alt=", 4))
            al++;
          if(al + 4 < gt) {
            al += 4;
            if(!isspace(*al)) {
              unsigned char q1 = *al;
              if(q1 == '\'' || q1 == '"')
                al++;
              {
                const unsigned char *e2 = al;
                Buffer ab = {NULL, 0, 0};
                size_t ql = q1 == '\'' || q1 == '"' ? 1 : 0;
                memset(&ab, 0, sizeof ab);
                while(e2 < gt && (ql ? (*e2 != q1) : (*e2 != '>' && *e2 != ' '))) {
                  if(*e2 == '&') {
                    const unsigned char *nx;
                    html_add_entity(&ab, e2, gt, &nx);
                    e2 = nx > e2 ? nx : e2 + 1;
                  }
                  else {
                    b_add(&ab, (const char *)e2, 1);
                    e2++;
                  }
                }
                if(ab.len) {
                  if(!lastw) {
                    b_add(o, " ", 1);
                    lastw = 1;
                  }
                  b_add(o, ab.data, ab.len);
                  lastw = 0;
                }
                free(ab.data);
              }
            }
          }
        }
      }
    }
  }
  while(o->len && (o->data[o->len - 1] == '\n' || o->data[o->len - 1] == '\t' ||
                   o->data[o->len - 1] == ' '))
    o->len--;
}
  static void write_buffered(Jb *jb, Res *res)
{
  Buffer rt;
  const unsigned char *data = (const unsigned char *)res->body.data;
  size_t len = res->body.len;
  int rendered = 0;
  if(res->streamed)
    return;
  if(!len)
    return;
  if(!jb->save_path[0] && memchr(res->body.data, '<', len)) {
    const unsigned char *look = (const unsigned char *)res->body.data;
    const unsigned char *le = (const unsigned char *)res->body.data + len;
    int is_html = 0;
    while(look < le) {
      const unsigned char *la = memchr(look, '<', (size_t)(le - look));
      if(!la)
        break;
      if(la + 1 < le &&
         (isalpha(la[1]) || la[1] == '/' || la[1] == '!' || la[1] == '?')) {
        is_html = 1;
        break;
      }
      look = la + 1;
    }
    if(is_html) {
      memset(&rt, 0, sizeof rt);
      html_to_text((const unsigned char *)res->body.data, len, &rt);
      if(!rt.len) {
        free(rt.data);
        return;
      }
      data = (const unsigned char *)rt.data;
      len = rt.len;
      rendered = 1;
    }
  }
  if(jb->save_path[0]) {
    FILE *f = fopen(jb->save_path, "wb");
    if(f) {
      fwrite(data, 1, len, f);
      fclose(f);
    }
    else {
      snprintf(res->err, sizeof res->err, "can't open %s", jb->save_path);
      res->net_ok = 0;
    }
  }
  else {
    pthread_mutex_lock(&g_omu);
    fwrite(data, 1, len, stdout);
    fflush(stdout);
    pthread_mutex_unlock(&g_omu);
  }
  if(rendered)
    free(rt.data);
}

static void print_summary(Jb *jb, Res *res, Cfg *cfg)
{
  char bs[16], rs[16];
  double el = res->ms / 1000.0;
  const char *c;

  if(cfg->silent)
    return;
  if(res->net_ok && res->status) {
    long long rate = el > 0 ? (long long)(res->bytes / el) : 0;
    fmt_size(res->bytes, bs);
    fmt_size(rate, rs);
    c = status_color(res->status);
    fprintf(stderr, "%svolley %s%3d%s  %-9s %7.2fs %8s/s  %s%s\n",
            CD, c, res->status, CK, bs, el, rs, jb->url, CK);
  }
  else {
    c = status_color(0);
    fprintf(stderr, "%svolley %s%4s%s  %s  %s%s\n",
            CD, c, "FAIL", CK, res->err, jb->url, CK);
  }
}

/* ---------------------------------------------------------------- */
/* recursive mirror: HTML + CSS link collection and crawler          */
/* ---------------------------------------------------------------- */
static char g_start_host[256] = "";

/* simple glob match: * ? and [abc]/[a-z] supported */
static int glob_match(const char *p, const char *s)
{
  for(;;) {
    if(*p == '*') {
      while(p[1] == '*')
        p++;
      if(!p[1])
        return 1;
      for(const char *t = s;; t++) {
        if(glob_match(p + 1, t))
          return 1;
        if(!*t)
          break;
      }
      return 0;
    }
    if(*p == '?') {
      if(!*s)
        return 0;
      p++; s++;
      continue;
    }
    if(*p == '[') {
      int neg = 0, hit = 0;
      const char *q = p + 1;
      if(*q == '!' || *q == '^') { neg = 1; q++; }
      if(*q == ']')
        q++;
      while(*q && *q != ']') {
        if(q[1] == '-' && q[2] && q[2] != ']') {
          if(*s >= q[0] && *s <= q[2])
            hit = 1;
          q += 3;
        }
        else {
          if(*s == *q)
            hit = 1;
          q++;
        }
      }
      if(*q != ']')
        return 0;
      if(neg)
        hit = !hit;
      if(!hit || !*s)
        return 0;
      p = q + 1; s++;
      continue;
    }
    if(*p != *s)
      return !*p && !*s ? 1 : 0;
    if(!*p)
      return 1;
    p++; s++;
  }
}

/* match a URL path against a comma/space separated wildcard list */
static int path_list_match(const char *list, const char *path)
{
  char tok[512];
  const char *p = list;
  while(*p) {
    while(*p == ',' || *p == ' ' || *p == '\t')
      p++;
    if(!*p)
      break;
    {
      const char *stage = p;
      size_t n = 0;
      while(*stage && *stage != ',' && *stage != ' ') {
        if(n < sizeof tok - 1)
          tok[n++] = *stage;
        stage++;
      }
      tok[n] = 0;
      p = stage;
    }
    if(glob_match(tok, path))
      return 1;
    /* allow matching against the trailing basename too */
    {
      const char *sl = strrchr(path, '/');
      if(sl && glob_match(tok, sl + 1))
        return 1;
    }
  }
  return 0;
}

static int host_allowed(const char *host)
{
  if(g_domains[0]) {
    char tok[512];
    const char *p = g_domains;
    int ok = 0;
    while(*p) {
      while(*p == ',' || *p == ' ' || *p == '\t')
        p++;
      if(!*p)
        break;
      {
        const char *stage = p;
        size_t n = 0;
        while(*stage && *stage != ',' && *stage != ' ')
          if(n < sizeof tok - 1)
            tok[n++] = *stage++;
          else
            stage++;
        tok[n] = 0;
        p = stage;
      }
      if(cookie_domain_match(tok, host)) {
        ok = 1;
        break;
      }
    }
    if(!ok)
      return 0;
  }
  if(g_span_hosts)
    return 1;
  if(!g_start_host[0])
    return 1;
  return !strcasecmp(host, g_start_host);
}

static int path_allowed(const char *path)
{
  if(g_accept[0] && !path_list_match(g_accept, path))
    return 0;
  if(g_reject[0] && path_list_match(g_reject, path))
    return 0;
  return 1;
}

/* value of an attribute inside a tag; *val/_vlen set to raw value */
static int tag_attr_val(const char *tag, size_t tlen, const char *attr,
                        const char **val, size_t *vlen)
{
  size_t al = strlen(attr);
  for(size_t i = 0; i + al <= tlen; i++) {
    if(strncasecmp(tag + i, attr, al))
      continue;
    if(i > 0 && (isalnum((unsigned char)tag[i - 1]) || tag[i - 1] == '_' ||
                 tag[i - 1] == '-'))
      continue;
    if(i + al < tlen && (isalnum((unsigned char)tag[i + al]) ||
                         tag[i + al] == '_' || tag[i + al] == '-'))
      continue;
    {
      size_t j = i + al;
      while(j < tlen && (tag[j] == ' ' || tag[j] == '\t' || tag[j] == '\r' ||
                         tag[j] == '\n'))
        j++;
      if(j < tlen && tag[j] == '=') {
        j++;
        while(j < tlen && (tag[j] == ' ' || tag[j] == '\t' ||
                           tag[j] == '\r' || tag[j] == '\n'))
          j++;
        if(j < tlen && (tag[j] == '"' || tag[j] == '\'')) {
          char q = tag[j++];
          const char *vs = tag + j;
          size_t l = 0;
          while(j < tlen && tag[j] != q) {
            j++;
            l++;
          }
          *val = vs;
          *vlen = l;
          return 1;
        }
        else {
          const char *vs = tag + j;
          size_t l = 0;
          while(j < tlen && tag[j] != ' ' && tag[j] != '\t' &&
                tag[j] != '>' && tag[j] != '\r' && tag[j] != '\n') {
            j++;
            l++;
          }
          *val = vs;
          *vlen = l;
          return 1;
        }
      }
    }
  }
  return 0;
}

typedef struct {
  char url[2048];
} MirLink;

static void mir_add(MirLink *links, int *nl, int max, const char *url)
{
  char abs[2048];
  if(*nl >= max)
    return;
  snprintf(abs, sizeof abs, "%s", url);
  {
    char *fh = strchr(abs, '#');
    if(fh)
      *fh = 0;
  }
  if(!abs[0])
    return;
  {
    Url uu;
    if(parse_url(abs, &uu) != 0)
      return;
    if(uu.proto != 0)
      return;   /* only http(s) crawlable */
    if(!host_allowed(uu.host))
      return;
    if(!path_allowed(uu.path))
      return;
  }
  if(!strncmp(abs, "javascript:", 11) || !strncmp(abs, "mailto:", 7) ||
     !strncmp(abs, "data:", 5) || !strncmp(abs, "tel:", 4))
    return;
  snprintf(links[*nl].url, sizeof links[0].url, "%s", abs);
  (*nl)++;
}

/* collect crawlable absolute links from an HTML or CSS body */
static int collect_links(const char *body, size_t len, const char *base,
                         MirLink *links, int max)
{
  int nl = 0;
  const char *end = body + len;
  const char *p = body;
  static const char *attrs[] = {
    "href", "src", "action", "poster", "data-src", "cite", NULL
  };
  char baseurl[2048] = "";
  snprintf(baseurl, sizeof baseurl, "%s", base);
  while((p = memchr(p, '<', (size_t)(end - p))) != NULL) {
    const char *gt = memchr(p, '>', (size_t)(end - p));
    if(!gt)
      break;
    const char *tag = p + 1;
    size_t tlen = (size_t)(gt - tag);
    const char *tn = tag;
    size_t tnl = 0;
    while(tnl < tlen && (isalnum((unsigned char)tn[tnl]) ||
                         tn[tnl] == '-' || tn[tnl] == '_'))
      tnl++;
    if(tnl == 0) {
      /* comment or doctype or declaration */
      p = gt + 1;
      if(tlen >= 3 && !strncasecmp(tag, "!--", 3)) {
        const char *ce = strstr(gt + 1, "-->");
        if(ce)
          p = ce + 3;
      }
      continue;
    }
    if(!strncasecmp(tag, "base ", 5) || !strncasecmp(tag, "base>", 5) ||
       !strncasecmp(tag, "base\t", 5)) {
      const char *v;
      size_t vl;
      if(tag_attr_val(tag, tlen, "href", &v, &vl)) {
        char bl[2048];
        snprintf(bl, sizeof bl, "%.*s", (int)(vl < 2047 ? vl : 2047), v);
        snprintf(baseurl, sizeof baseurl, "%s", bl);
      }
    }
    const char *v;
    size_t vl;
    for(int ai = 0; attrs[ai]; ai++) {
      if(tag_attr_val(tag, tlen, attrs[ai], &v, &vl)) {
        char lk[2048];
        snprintf(lk, sizeof lk, "%.*s", (int)(vl < 2047 ? vl : 2047), v);
        if(!*lk || !strncmp(lk, "#", 1))
          continue;
        {
          char abs[2048];
          resolve_url(baseurl, lk, abs, sizeof abs);
          mir_add(links, &nl, max, abs);
        }
      }
    }
    {
      char srcset[4096];
      if(tag_attr_val(tag, tlen, "srcset", &v, &vl)) {
        snprintf(srcset, sizeof srcset, "%.*s",
                 (int)(vl < 4095 ? vl : 4095), v);
        char *t = srcset;
        while(*t) {
          while(*t == ' ' || *t == '\t' || *t == ',' || *t == '\n' ||
                *t == '\r')
            t++;
          if(!*t)
            break;
          {
            char url[1024];
            size_t n = 0;
            while(*t && *t != ' ' && *t != '\t' && *t != ',' &&
                  *t != '\n' && *t != '\r') {
              if(n < sizeof url - 1)
                url[n++] = *t++;
              else
                t++;
            }
            url[n] = 0;
            {
              char abs[2048];
              resolve_url(baseurl, url, abs, sizeof abs);
              mir_add(links, &nl, max, abs);
            }
            while(*t && *t != ',' && *t != '\t' && *t != '\n' && *t != '\r')
              t++;
          }
        }
      }
    }
    p = gt + 1;
  }
  /* CSS url() / @import scanning (harmless within HTML too) */
  {
    const char *q = body;
    while((q = (const char *)memchr(q, 'u', (size_t)(end - q))) != NULL) {
      if((size_t)(end - q) >= 4 && !strncasecmp(q, "url(", 4)) {
        const char *s = q + 4;
        const char *e2;
        while(s < end && (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n'))
          s++;
        if(s < end && (*s == '"' || *s == '\'')) {
          char qc = *s++;
          e2 = s;
          while(e2 < end && *e2 && *e2 != qc)
            e2++;
        }
        else {
          e2 = s;
          while(e2 < end && *e2 != ')' && *e2 != ' ' && *e2 != '\t' &&
                *e2 != ';' && *e2 != '\r' && *e2 != '\n')
            e2++;
        }
        if(s < end) {
          char url[2048];
          size_t ul = (size_t)(e2 - s);
          snprintf(url, sizeof url, "%.*s",
                   (int)(ul < 2047 ? ul : 2047), s);
          {
            char abs[2048];
            resolve_url(baseurl, url, abs, sizeof abs);
            mir_add(links, &nl, max, abs);
          }
        }
        q = (e2 < end) ? e2 : end;
      }
      else
        q++;
    }
    q = body;
    while((q = (const char *)memchr(q, '@', (size_t)(end - q))) != NULL) {
      char url[2048];
      const char *s;
      const char *se;
      size_t ul;
      if((size_t)(end - q) >= 7 && !strncasecmp(q, "@import", 7)) {
        s = q + 7;
        while(s < end && (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n'))
          s++;
        if(s < end && (*s == '"' || *s == '\'')) {
          char qc = *s++;
          se = s;
          while(se < end && *se && *se != qc)
            se++;
        }
        else {
          se = s;
          while(se < end && *se != ';' && *se != '\n' && *se != '\r' &&
                *se != ' ')
            se++;
        }
        ul = (size_t)(se - s);
        snprintf(url, sizeof url, "%.*s", (int)(ul < 2047 ? ul : 2047), s);
        {
          char abs[2048];
          resolve_url(baseurl, url, abs, sizeof abs);
          mir_add(links, &nl, max, abs);
        }
      }
      q++;
    }
  }
  return nl;
}

static void mirror_mkdirs(const char *savepath)
{
  char tmp[2048];
  snprintf(tmp, sizeof tmp, "%s", savepath);
  char *slash = tmp;
  while((slash = strchr(slash + 1, '/')) != NULL) {
    *slash = 0;
    if(tmp[0])
      mkdir(tmp, 0755);
    *slash = '/';
  }
}

/* compute the on-disk path for an absolute url under g_dprefix */
static void mirror_save_path(const char *absurl, int want_host_dir, char *out,
                             size_t cap)
{
  Url u;
  char path[2048];
  size_t pl;
  if(parse_url(absurl, &u) != 0) {
    snprintf(out, cap, "%s", "index.html");
    return;
  }
  snprintf(path, sizeof path, "%s", u.path);
  {
    char *q = strchr(path, '?');
    if(q)
      *q = 0;
  }
  {
    char *h = strchr(path, '#');
    if(h)
      *h = 0;
  }
  pl = strlen(path);
  if(!pl)
    snprintf(path, sizeof path, "/index.html");
  else if(path[pl - 1] == '/')
    snprintf(path + pl, sizeof path - pl, "index.html");
  {
    const char *last = strrchr(path, '/');
    const char *name = last ? last + 1 : path;
    if(!*name)
      snprintf(path + strlen(path), sizeof path - strlen(path), "index.html");
  }
  /* strip any leading slash */
  {
    const char *pp = path;
    while(*pp == '/')
      pp++;
    if(want_host_dir)
      snprintf(out, cap, "%s/%s/%s", g_dprefix, u.host, pp);
    else
      snprintf(out, cap, "%s/%s", g_dprefix, pp);
  }
}

static int mirror_engine(Cfg *cfg, Jb *jobs, int nurls)
{
  typedef struct {
    char url[2048];
    int depth;
  } Qe;
  enum { MAXQ = 40000 };
  static Qe *q = NULL;
  int qh = 0, qt = 0;
  char *(*seen) = NULL;
  int nseen = 0, seen_cap = 0;
  int rc = 0;
  int saved_segs;

  g_mirror_active = 1;
  if(!q)
    q = malloc((size_t)MAXQ * sizeof *q);
  if(!q)
    return 1;
  if(!g_dprefix[0])
    strcpy(g_dprefix, ".");

  /* prevent the segmented fast-path during a crawl; one stream each */
  saved_segs = cfg->segs;
  cfg->segs = 1;

  for(int i = 0; i < nurls && qt < MAXQ; i++) {
    char norm[2048];
    snprintf(norm, sizeof norm, "%s", jobs[i].url);
    {
      char *frag = strchr(norm, '#');
      if(frag)
        *frag = 0;
    }
    if(!g_start_host[0]) {
      Url su;
      if(parse_url(norm, &su) == 0 && su.host[0])
        snprintf(g_start_host, sizeof g_start_host, "%s", su.host);
    }
    snprintf(q[qt].url, sizeof q[0].url, "%s", norm);
    q[qt].depth = 1;
    qt++;
  }

  while(qh < qt) {
    Qe cur = q[qh++];
    Url u;
    Jb jb;
    Res res;
    char found = 0;

    for(int s2 = 0; s2 < nseen; s2++)
      if(!strcmp(seen[s2], cur.url)) {
        found = 1;
        break;
      }
    if(found)
      continue;
    if(nseen >= seen_cap) {
      int nc = seen_cap ? seen_cap * 2 : 256;
      char **ns = realloc(seen, (size_t)nc * sizeof *ns);
      if(!ns)
        goto done;
      seen = ns;
      seen_cap = nc;
    }
    seen[nseen] = strdup(cur.url);
    if(!seen[nseen])
      goto done;
    nseen++;

    if(parse_url(cur.url, &u) != 0)
      continue;
    if(u.proto != 0)
      continue;
    if(!host_allowed(u.host))
      continue;
    if(!path_allowed(u.path))
      continue;
    if(g_level > 0 && cur.depth > g_level)
      continue;

    memset(&jb, 0, sizeof jb);
    jb.url = cur.url;
    jb.u = u;
    memset(&res, 0, sizeof res);
    res.bytes = -1;
    res.total = -1;
    run_job(cfg, &jb, &res);

    if(!res.net_ok) {
      if(!cfg->silent)
        fprintf(stderr, "%svolley  FAIL  %s  %s%s\n", CD, res.err, cur.url, CK);
      rc = 1;
      free(res.body.data);
      continue;
    }

    {
      char outpath[4096];
      mirror_save_path(res.final_url[0] ? res.final_url : cur.url,
                       g_mirror != 0, outpath, sizeof outpath);
      mirror_mkdirs(outpath);
      {
        FILE *f = fopen(outpath, "wb");
        if(f && res.body.data && res.body.len) {
          fwrite(res.body.data, 1, res.body.len, f);
          fclose(f);
        }
        else if(f) {
          fclose(f);
        }
        else if(!cfg->silent) {
          fprintf(stderr, "%svolley  FAIL  can't write %s%s\n", CD, outpath,
                  CK);
          rc = 1;
        }
      }
      if(!cfg->silent)
        fprintf(stderr, "%svolley  %3d  %s -> %s%s\n", CD, res.status,
                cur.url, outpath, CK);
    }

    /* crawlable? parse html/css bodies */
    {
      int is_css = 0;
      {
        const char *pl = strrchr(u.path, '.');
        if(pl && !strcasecmp(pl, ".css"))
          is_css = 1;
      }
      if(res.body.data && res.body.len &&
         (is_css || memchr(res.body.data, '<', res.body.len)))
      {
        MirLink *links = malloc(sizeof *links * 1024);
        int nl = 0;
        if(links) {
          nl = collect_links(res.body.data, res.body.len,
                             res.final_url[0] ? res.final_url : cur.url,
                             links, 1024);
          for(int li = 0; li < nl && qt < MAXQ; li++) {
            int dup = 0;
            for(int s2 = 0; s2 < nseen; s2++)
              if(!strcmp(seen[s2], links[li].url)) {
                dup = 1;
                break;
              }
            if(dup)
              continue;
            snprintf(q[qt].url, sizeof q[0].url, "%s", links[li].url);
            q[qt].depth = cur.depth + 1;
            qt++;
          }
          free(links);
        }
      }
    }
    free(res.body.data);
  }

done:
  cfg->segs = saved_segs;
  if(!cfg->silent)
    fprintf(stderr, "%svolley> crawl done: %d urls fetched, %d queued%s\n",
            CD, nseen, qt - nseen, CK);
  free(q);
  q = NULL;
  for(int i = 0; i < nseen; i++)
    free(seen[i]);
  free(seen);
  g_mirror_active = 0;
  return rc;
}
/* ---------------------------------------------------------------- */
/* dispatcher: run N urls across M worker threads                    */
/* ---------------------------------------------------------------- */
typedef struct {
  Cfg *cfg;
  Jb *jobs;
  int njobs;
  int next;
  int *fails;
  pthread_mutex_t qmu;
} Pool;

static void *job_worker(void *arg)
{
  Pool *p = arg;
  for(;;) {
    int idx;
    Res res;
    int attempt;
    pthread_mutex_lock(&p->qmu);
    if(p->next >= p->njobs) {
      pthread_mutex_unlock(&p->qmu);
      break;
    }
    idx = p->next++;
    pthread_mutex_unlock(&p->qmu);

    attempt = 0;
    memset(&res, 0, sizeof res);
    run_job(p->cfg, &p->jobs[idx], &res);
    while(!res.net_ok || (p->cfg->fail_on_http && res.http_err)) {
      if(res.streamed || attempt >= g_retries)
        break;
      if(res.net_ok) {
        /* an HTTP-level failure: only retried under --retry-all-errors
           (and never for 4xx, which are usually permanent) */
        if(!g_retry_all || (res.status >= 400 && res.status < 500))
          break;
      }
      attempt++;
      pool_flush_all();
      if(g_retry_wait > 0) {
        struct timespec ts;
        ts.tv_sec = g_retry_wait;
        ts.tv_nsec = 0;
        nanosleep(&ts, NULL);
      }
      free(res.body.data);
      memset(&res, 0, sizeof res);
      run_job(p->cfg, &p->jobs[idx], &res);
    }

    write_buffered(&p->jobs[idx], &res);
    print_summary(&p->jobs[idx], &res, p->cfg);

    free(res.body.data);
    if(!res.net_ok || (p->cfg->fail_on_http && res.http_err))
      p->fails[idx] = 1;
  }
  return NULL;
}

/* ---------------------------------------------------------------- */
/* help                                                              */
/* ---------------------------------------------------------------- */
#ifndef VOLLEY_LIB

/* parse a size like "100k" / "5M" / "1G" into bytes; 0 on no number */
static long long parse_size(const char *s)
{
  long long v = 0;
  int any = 0;
  while(*s && *s >= '0' && *s <= '9') {
    v = v * 10 + (*s - '0');
    s++;
    any = 1;
  }
  if(!any)
    return 0;
  if(*s) {
    switch(tolower((unsigned char)*s)) {
    case 'k': v *= 1024LL; break;
    case 'm': v *= 1024LL * 1024; break;
    case 'g': v *= 1024LL * 1024 * 1024; break;
    default: break;
    }
  }
  return v;
}

static void conf_add_header(const char *line)
{
  if(g_nconfh < 64) {
    g_conf_hdrs[g_nconfh] = strdup(line);
    if(g_conf_hdrs[g_nconfh])
      g_nconfh++;
  }
}

/* wgetrc-style configuration file (like wget's init.c command table):
   one "command = value" per line, '#' comments are supported. */
static void run_config_file(FILE *f)
{
  char line[4096];
  while(fgets(line, sizeof line, f)) {
    char *p = line, *cmd, *val, *eq;
    char c2[1024], v2[1024];
    while(*p == ' ' || *p == '\t') p++;
    if(*p == '#' || *p == '\n' || *p == 0)
      continue;
    eq = strchr(p, '=');
    if(!eq)
      continue;
    *eq = 0;
    cmd = p;
    val = eq + 1;
    for(char *q = cmd; *q; q++)
      if(*q == '\n' || *q == '\r' || *q == ' ' || *q == '\t')
        *q = 0;
    while(*val == ' ' || *val == '\t') val++;
    {
      size_t vl = strlen(val);
      while(vl && (val[vl-1] == '\n' || val[vl-1] == '\r' ||
                   val[vl-1] == ' ' || val[vl-1] == '\t'))
        val[--vl] = 0;
    }
    /* de-hyphenate, case-insensitive keys */
    for(char *q = cmd; *q; q++) {
      if(*q == '-' || *q == '_')
        *q = 0;
      *q = (char)tolower((unsigned char)*q);
    }
    for(char *q = cmd; q && *q == 0; q++) ;
    snprintf(c2, sizeof c2, "%s", cmd);
    snprintf(v2, sizeof v2, "%s", val);
    if(!strcmp(c2, "connecttimeout"))
      g_conn_timeout = atol(v2);
    else if(!strcmp(c2, "maxtime") || !strcmp(c2, "timeout"))
      g_timeout = atol(v2) > 0 ? atol(v2) : 0;
    else if(!strcmp(c2, "useragent"))
      g_conf_ua = strdup(v2);
    else if(!strcmp(c2, "cookies")) {
      if(!strcasecmp(v2, "off") || !strcmp(v2, "0"))
        g_cook_enabled = 0;
      else if(!strcasecmp(v2, "on"))
        g_cook_enabled = 1;
    }
    else if(!strcmp(c2, "loadcookies")) {
      cookie_jar_load(v2);
      g_cook_use = 1;
      g_cook_enabled = 1;
    }
    else if(!strcmp(c2, "savecookies")) {
      snprintf(g_cook_file, sizeof g_cook_file, "%s", v2);
      g_cook_save = 1;
    }
    else if(!strcmp(c2, "progress")) {
      if(!strcasecmp(v2, "dot"))
        g_progstyle = 1;
      else if(!strcasecmp(v2, "bar"))
        g_progstyle = 0;
      else if(!strncmp(v2, "dot:", 4)) {
        g_progstyle = 1;
        g_dot_bytes = 1024;
        sscanf(v2 + 4, "%d", &g_dot_bytes);
        if(g_dot_bytes <= 0)
          g_dot_bytes = 1024;
      }
    }
    else if(!strcmp(c2, "limitrate")) {
      g_limit_rate = parse_size(v2);
      if(g_limit_rate <= 0)
        g_limit_rate = atoll(v2);
    }
    else if(!strcmp(c2, "tries") || !strcmp(c2, "retry"))
      g_retries = atoi(v2);
    else if(!strcmp(c2, "retrydelay"))
      g_retry_wait = atol(v2);
    else if(!strcmp(c2, "retryalerrors"))
      g_retry_all = !strcasecmp(v2, "on") || !strcmp(v2, "1");
    else if(!strcmp(c2, "netrc"))
      g_netrc = !strcasecmp(v2, "on") || !strcmp(v2, "1");
    else if(!strcmp(c2, "noproxy"))
      snprintf(g_no_proxy, sizeof g_no_proxy, "%s", v2);
    else if(!strcmp(c2, "recursive"))
      g_recursive = !strcasecmp(v2, "on") || !strcmp(v2, "1");
    else if(!strcmp(c2, "reclevel") || !strcmp(c2, "level"))
      g_level = atoi(v2);
    else if(!strcmp(c2, "domains"))
      snprintf(g_domains, sizeof g_domains, "%s", v2);
    else if(!strcmp(c2, "spanhosts"))
      g_span_hosts = !strcasecmp(v2, "on") || !strcmp(v2, "1");
    else if(!strcmp(c2, "accept"))
      snprintf(g_accept, sizeof g_accept, "%s", v2);
    else if(!strcmp(c2, "reject"))
      snprintf(g_reject, sizeof g_reject, "%s", v2);
    else if(!strcmp(c2, "mirror"))
      g_mirror = !strcasecmp(v2, "on") || !strcmp(v2, "1");
    else if(!strcmp(c2, "directoryprefix"))
      snprintf(g_dprefix, sizeof g_dprefix, "%s", v2);
    else if(!strcmp(c2, "header"))
      conf_add_header(v2);
    else if(!strcmp(c2, "httponly") || !strcmp(c2, "nohttp2")) {
      g_http2 = 0;
      g_alpn_h2 = 0;
    }
  }
}

static void config_load(const char *explicit)
{
  FILE *f = NULL;
  if(explicit && explicit[0]) {
    f = fopen(explicit, "r");
    if(!f)
      fprintf(stderr, "volley: cannot open config file %s: %s\n",
              explicit, strerror(errno));
  }
  else {
    const char *home = getenv("HOME");
    char path[1024];
    if(home && *home) {
      snprintf(path, sizeof path, "%s/.volleyrc", home);
      if(access(path, R_OK) == 0)
        f = fopen(path, "r");
    }
    if(!f && home && *home) {
      snprintf(path, sizeof path, "%s/.wgetrc", home);
      if(access(path, R_OK) == 0)
        f = fopen(path, "r");
    }
  }
  if(f) {
    run_config_file(f);
    fclose(f);
  }
}

static void volley_help(void)
{
  puts("_   _       _ _\n"
        "| | | |     | | |\n"
        "| | | | ___ | | | ___ _   _\n"
        "| | | |/ _ \\| | |/ _ \\ | | |\n"
        "\\ \\_/ / (_) | | |  __/ |_| |\n"
        " \\___/ \\___/|_|_|\\___|\\__, |\n"
        "                       __/ |\n"
        "                      |___/\n"
        "\n"
        "volley v" VOLLEY_VERSION " - fetch your URLs, faster.\n"
       " usage: volley [options...] <url>...\n"
" volley clone <git-url> [dir]    clone a git repo, no git needed\n"
        " volley ls-remote <url> [ref...] list a remote's advertised refs\n"
        " volley init [dir]               create an empty git repository\n"
        " volley branch | tag             list local branches or tags\n"
        " volley remote [-v] [add n url]  show or add git remotes\n"
        " volley rev-parse <ref>...       resolve refs to object ids\n"
        " volley cat-file -t|-p|-s <obj>  object type, content or size\n"
        " volley log [<n>] [<ref>]        commit history, oneline style\n"
        " volley ls-tree [<treeish>]      pretty-list a tree\n"
        "                                 git commands take -C <dir>\n"
       " options:\n"
       "  -X, --request <m>     HTTP method to use (GET, POST, PUT, ...)\n"
       "  -H, --header <h>      extra header line, like 'X-Api: key' (repeatable)\n"
       "  -d, --data <data>     send data as a POST body (repeatable, &-joined)\n"
       "  -F, --form <f>        multipart form field 'name=value' or 'name=@file'\n"
       "  -T, --upload-file <f> upload a file (PUT, application/octet-stream)\n"
       "  -b, --cookie <c>      cookie string 'n=v; ...' or a cookie file to load\n"
       "      --cookie-jar <f>  save new cookies to <f> (Netscape format)\n"
       "      --junk-session-cookies  don't write session cookies to the jar\n"
       "  -o, --output <file>   write output to <file> instead of stdout\n"
       "  -O, --remote-name     write output named as the remote file\n"
       "  -I, --head            fetch headers only (HEAD)\n"
       "  -j, --parallel <n>    fetch <n> urls at once (0 = auto)\n"
       "  -c, --segments <n>    segmented parallel download via Range (1 = off)\n"
       "  -C, --continue-at <n> resume a download at byte <n> ('-' = from file size)\n"
       "  -k, --insecure        allow insecure TLS connections\n"
       "  -4, --ipv4            resolve to ipv4 addresses only\n"
       "  -6, --ipv6            resolve to ipv6 addresses only\n"
       "  -L, --location        follow redirects (default)\n"
       "      --no-location     do not follow redirects\n"
       "  -r, --range <range>   request a byte range (RFC 7233)\n"
       "  -u, --user <u:p>      use basic auth with these credentials\n"
       "  -A, --user-agent <ua> send a custom User-Agent\n"
       "  -m, --max-time <secs> overall operation timeout\n"
       "      --connect-timeout <secs>  separate connect timeout\n"
       "      --retry <n>       retry failed transfers <n> times\n"
       "      --retry-all-errors\n"
       "      --retry-delay <s> seconds to wait between retries\n"
       "      --limit-rate <spd> cap the download speed (e.g. 100k, 2M)\n"
       "      --progress <bar|dot>  progress meter style\n"
       "      --netrc           read .netrc for login/password\n"
       "  -K, --config <file>   read a wgetrc-style config file\n"
       "      --http2           try HTTP/2 (ALPN only, single request)\n"
       "      --http11          force HTTP/1.1 (alias of --http1.1)\n"
       "      --client-cert F   TLS client certificate (PEM) for mTLS\n"
       "      --client-key F    private key for the client certificate (PEM)\n"
        "  -S, --session <name>  persistent per-host session (headers+cookies)\n"
        "                        name with a '/' is treated as a literal path\n"
        "      --chunked         stream -T upload with Transfer-Encoding: chunked\n"
       "      --recursive / --mirror  fetch linked pages (html + css)\n"
       "      --level <n>       recursion depth (0 = infinite)\n"
       "      --domains <a,b>   stay inside these hosts\n"
       "      --span-hosts      allow following links to other hosts\n"
       "      --accept <list>, --reject <list>  accept/reject name patterns\n"
       "  -l, --list-only       FTP: list directory names only (NLST)\n"
       "  -x, --proxy <proxy>   use proxy: http://h:p, socks5://h:p (or socks5h://)\n"
       "  -U, --proxy-user <u>  credentials for the proxy (user:pass)\n"
       "  -i, --include         include the response headers in the output\n"
       "  -v, --verbose         talkative output (like curl -v)\n"
       "  -s, --silent          no progress meter, no summary\n"
       "  -f, --fail            exit non-zero on HTTP errors (>= 400)\n"
       "      --color <mode>    auto | always | never\n"
       "      --no-encoding     do not decode gzip/deflate responses\n"
       "  -V, --version         print the version and exit\n"
       "  -h, --help            this help text\n"
       " gzip/deflate responses are transparently decoded by default.");
}
#endif /* !VOLLEY_LIB */

/* ---------------------------------------------------------------- */
/* shared engine lifecycle (CLI and library)                         */
/* ---------------------------------------------------------------- */
static int g_engine_ready = 0;

static int engine_start(void)
{
  if(g_engine_ready)
    return 0;
  signal(SIGPIPE, SIG_IGN);
  signal(SIGWINCH, on_sigwinch);
  prog_size();
  if(g_timeout <= 0)
    g_timeout = 30;
  for(int pi = 0; pi < VOLLEY_MAX_POOL; pi++)
    g_pool[pi].fd = -1;
  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
                   OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
  g_ctx = SSL_CTX_new(TLS_client_method());
  if(!g_ctx)
    return -1;
  SSL_CTX_set_verify(g_ctx, SSL_VERIFY_PEER, NULL);
  {
    static const char *bundles[] = {
      "/etc/ssl/certs/ca-certificates.crt",
      "/etc/pki/tls/certs/ca-bundle.crt",
      "/usr/local/share/certs/ca-root-nss.crt",
      NULL
    };
    int loaded = 0;
    for(int bi = 0; bundles[bi]; bi++) {
      if(SSL_CTX_load_verify_locations(g_ctx, bundles[bi], NULL) == 1) {
        loaded = 1;
        break;
      }
    }
    if(!loaded)
      SSL_CTX_set_default_verify_paths(g_ctx);
  }
  if(g_certfile[0] || g_keyfile[0]) {
    if(!g_certfile[0] || !g_keyfile[0]) {
      snprintf(g_lasterr, sizeof g_lasterr,
               "--client-cert and --client-key must be used together");
      fprintf(stderr, "volley: %s\n", g_lasterr);
      return -1;
    }
    if(SSL_CTX_use_certificate_chain_file(g_ctx, g_certfile) != 1) {
      snprintf(g_lasterr, sizeof g_lasterr, "can't load client certificate %s: %s",
               g_certfile, ERR_error_string(ERR_get_error(), NULL));
      fprintf(stderr, "volley: %s\n", g_lasterr);
      return -1;
    }
    if(SSL_CTX_use_PrivateKey_file(g_ctx, g_keyfile, SSL_FILETYPE_PEM) != 1) {
      snprintf(g_lasterr, sizeof g_lasterr, "can't load client key %s: %s",
               g_keyfile, ERR_error_string(ERR_get_error(), NULL));
      fprintf(stderr, "volley: %s\n", g_lasterr);
      return -1;
    }
    if(SSL_CTX_check_private_key(g_ctx) != 1) {
      snprintf(g_lasterr, sizeof g_lasterr,
               "client private key %s does not match certificate %s",
               g_keyfile, g_certfile);
      fprintf(stderr, "volley: %s\n", g_lasterr);
      return -1;
    }
  }
  g_engine_ready = 1;
  return 0;
}

static void engine_cleanup(void)
{
  if(!g_engine_ready)
    return;
  for(int i = 0; i < VOLLEY_MAX_POOL; i++) {
    if(g_pool[i].fd >= 0) {
      if(g_pool[i].ssl)
        SSL_free(g_pool[i].ssl);
      close(g_pool[i].fd);
      g_pool[i].fd = -1;
    }
  }
  SSL_CTX_free(g_ctx);
  g_ctx = NULL;
  g_engine_ready = 0;
}

/* ---------------------------------------------------------------- */
/* git clone without git: smart HTTP transport                       */
/* ---------------------------------------------------------------- */
typedef struct {
  unsigned char oid[20];
  int has_oid;
  int type;                 /* 1 commit, 2 tree, 3 blob, 4 tag, 6-7 delta */
  long long size;
  unsigned char *data;
  long long base_off;
  long long pack_off;
  int base_set;
  unsigned char base_oid[20];
  int resolved;
} GObj;

static void hex16(char *out, const unsigned char *p)
{
  static const char d[] = "0123456789abcdef";
  for(int i = 0; i < 20; i++) {
    out[i*2]   = d[p[i] >> 4];
    out[i*2+1] = d[p[i] & 15];
  }
  out[40] = 0;
}

static int unhex1(char c)
{
  if(c >= '0' && c <= '9') return c - '0';
  if(c >= 'a' && c <= 'f') return c - 'a' + 10;
  if(c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int hex20(const char *s, unsigned char *out)
{
  for(int i = 0; i < 20; i++) {
    int a = unhex1(s[i*2]);
    int b = unhex1(s[i*2+1]);
    if(a < 0 || b < 0)
      return -1;
    out[i] = (unsigned char)((a << 4) | b);
  }
  return s[40] == 0 ? 0 : -1;
}

static void git_sha1(const unsigned char *p, size_t n, unsigned char *out)
{
  EVP_MD_CTX *c = EVP_MD_CTX_new();
  if(!c)
    return;
  EVP_DigestInit_ex(c, EVP_sha1(), NULL);
  EVP_DigestUpdate(c, p, n);
  EVP_DigestFinal_ex(c, out, NULL);
  EVP_MD_CTX_free(c);
}

static const char *git_type_name(int t)
{
  switch(t) {
  case 1: return "commit";
  case 2: return "tree";
  case 3: return "blob";
  case 4: return "tag";
  }
  return "?";
}

static int git_inflate_all(const unsigned char *in, size_t n, Buffer *out)
{
  z_stream z;
  int r;
  char ob[8192];
  memset(&z, 0, sizeof z);
  if(inflateInit2(&z, 15 + 32) != Z_OK)
    return -1;
  z.next_in = (Bytef *)(unsigned char *)in;
  z.avail_in = (uInt)n;
  for(;;) {
    z.next_out = (Bytef *)ob;
    z.avail_out = (uInt)sizeof ob;
    r = inflate(&z, Z_NO_FLUSH);
    {
      size_t have = sizeof ob - z.avail_out;
      if(have && b_add(out, ob, have) != 0) {
        inflateEnd(&z);
        return -1;
      }
    }
    if(r == Z_STREAM_END)
      break;
    if(r != Z_OK && r != Z_BUF_ERROR) {
      inflateEnd(&z);
      return -1;
    }
    if(!z.avail_in && z.avail_out == (uInt)sizeof ob) {
      inflateEnd(&z);
      return -1;
    }
  }
  inflateEnd(&z);
  return 0;
}

static int git_inflate_obj(const unsigned char *in, size_t n, long long expect,
                           unsigned char **out, size_t *consumed)
{
  z_stream z;
  int r;
  unsigned char *buf;
  size_t cap, used = 0;
  memset(&z, 0, sizeof z);
  if(inflateInit(&z) != Z_OK)
    return -1;
  cap = (expect > 0) ? (size_t)expect + 1 : 4096;
  buf = malloc(cap);
  if(!buf) {
    inflateEnd(&z);
    return -1;
  }
  z.next_in = (Bytef *)(unsigned char *)in;
  z.avail_in = (uInt)n;
  for(;;) {
    z.next_out = buf + used;
    z.avail_out = (uInt)(cap - used - 1);
    if((int)cap - (int)used - 1 <= 0) {
      size_t ncap = cap * 2;
      unsigned char *nb = realloc(buf, ncap);
      if(!nb) {
        free(buf);
        inflateEnd(&z);
        return -1;
      }
      buf = nb;
      cap = ncap;
      continue;
    }
    r = inflate(&z, Z_NO_FLUSH);
    used = cap - 1 - z.avail_out;
    if(r == Z_STREAM_END)
      break;
    if(r != Z_OK && r != Z_BUF_ERROR) {
      free(buf);
      inflateEnd(&z);
      return -1;
    }
    if(!z.avail_in && z.avail_out == (uInt)(cap - used - 1)) {
      free(buf);
      inflateEnd(&z);
      return -1;
    }
  }
  inflateEnd(&z);
  if(consumed)
    *consumed = n - z.avail_in;
  *out = buf;
  return 0;
}

static unsigned long long git_varint(const unsigned char **p, const unsigned char *end)
{
  unsigned long long v = 0;
  int sh = 0;
  const unsigned char *d = *p;
  while(d < end) {
    unsigned char c = *d++;
    v |= (unsigned long long)(c & 0x7f) << sh;
    sh += 7;
    if(!(c & 0x80))
      break;
  }
  *p = d;
  return v;
}

static unsigned long long git_ofs(const unsigned char **p)
{
  unsigned long long v;
  const unsigned char *d = *p;
  unsigned char c = *d++;
  v = c & 0x7f;
  while(c & 0x80) {
    c = *d++;
    v = ((v + 1) << 7) | (c & 0x7f);
  }
  *p = d;
  return v;
}

static int git_apply_delta(const unsigned char *base, size_t bsz,
                           const unsigned char *d, size_t dsz,
                           unsigned char **out, size_t *osz)
{
  const unsigned char *p = d, *end = d + dsz;
  unsigned long long bsz2, zsz;
  unsigned char *res;
  size_t pos = 0;
  if((size_t)(end - p) < 2)
    return -1;
  bsz2 = git_varint(&p, end);
  zsz = git_varint(&p, end);
  if(bsz2 != (unsigned long long)bsz)
    return -1;
  if(zsz > (1ULL << 28))
    return -1;
  res = malloc((size_t)zsz + 1);
  if(!res)
    return -1;
  while(p < end) {
    unsigned char op = *p++;
    if(op & 0x80) {
      unsigned long long ofs = 0, size = 0;
      if(op & 0x01) { if(p >= end) goto bad; ofs |= (unsigned long long)*p++; }
      if(op & 0x02) { if(p >= end) goto bad; ofs |= (unsigned long long)*p++ << 8; }
      if(op & 0x04) { if(p >= end) goto bad; ofs |= (unsigned long long)*p++ << 16; }
      if(op & 0x08) { if(p >= end) goto bad; ofs |= (unsigned long long)*p++ << 24; }
      if(op & 0x10) { if(p >= end) goto bad; size |= (unsigned long long)*p++; }
      if(op & 0x20) { if(p >= end) goto bad; size |= (unsigned long long)*p++ << 8; }
      if(op & 0x40) { if(p >= end) goto bad; size |= (unsigned long long)*p++ << 16; }
      if(size == 0)
        size = 0x10000ULL;
      if(ofs + size > bsz || pos + (size_t)size > (size_t)zsz)
        goto bad;
      memcpy(res + pos, base + ofs, (size_t)size);
      pos += (size_t)size;
    }
    else if(op) {
      if((size_t)(end - p) < op || pos + op > (size_t)zsz)
        goto bad;
      memcpy(res + pos, p, op);
      p += op;
      pos += op;
    }
    else
      goto bad;
  }
  if(pos != (size_t)zsz)
    goto bad;
  *out = res;
  *osz = (size_t)zsz;
  return 0;
bad:
  free(res);
  return -1;
}

static int git_http(const char *url, const char *method,
                    const char *body, size_t blen,
                    const char *ctype, const char *accept,
                    Buffer *out, int *status,
                    char *err, size_t errsz)
{
  Cfg cfg;
  Jb jb;
  XOpt xo;
  Res res;
  char accept_hdr[256], ctype_hdr[160];
  char *uhdrs[2] = {NULL, NULL};

  memset(&cfg, 0, sizeof cfg);
  strcpy(cfg.method, method);
  cfg.nurls = 1;
  cfg.parallel = 1;
  cfg.segs = 1;
  cfg.follow = 1;
  cfg.silent = 1;
  cfg.body = (char *)body;
  cfg.body_len = blen;
  if(ctype)
    snprintf(ctype_hdr, sizeof ctype_hdr, "Content-Type: %s", ctype);
  if(accept)
    snprintf(accept_hdr, sizeof accept_hdr, "Accept: %s", accept);
  {
    int k = 0;
    if(ctype) uhdrs[k++] = ctype_hdr;
    if(accept) uhdrs[k++] = accept_hdr;
    cfg.uhdrs = uhdrs;
    cfg.nuhdrs = k;
  }

  memset(&jb, 0, sizeof jb);
  jb.url = url;
  if(parse_url(url, &jb.u) != 0) {
    snprintf(err, errsz, "malformed url: %s", url);
    return -1;
  }
  memset(&xo, 0, sizeof xo);
  xo.no_decode = 1;
  do_transfer(&cfg, &jb, &res, &xo);
  *status = res.status;
  if(!res.net_ok) {
    snprintf(err, errsz, "%s", res.err[0] ? res.err : "request failed");
    return -1;
  }
  out->data = res.body.data;
  out->len = res.body.len;
  out->cap = res.body.cap;
  return 0;
}

typedef struct {
  char name[300];
  unsigned char oid[20];
} GRef;

typedef struct {
  char repo[4096];
  int verbose;
  int quiet;
  int bare;
  GRef *refs;
  int nrefs;
  char branch[300];
  unsigned char head_oid[20];
  int have_head;
} GClone;

static int git_fetch_refs(GClone *gc, char *err, size_t errsz)
{
  char url[4300], line[3000];
  Buffer b;
  int status = 0;
  size_t pos = 0;
  int service_ok = 0;
  char caps[2048] = "";

  memset(&b, 0, sizeof b);
  snprintf(url, sizeof url, "%s/info/refs?service=git-upload-pack", gc->repo);
  if(git_http(url, "GET", NULL, 0, NULL, "application/x-git-upload-pack-advertisement",
              &b, &status, err, errsz) != 0)
    return -1;
  if(status >= 400) {
    snprintf(err, errsz, "repository not found (status %d) at %s", status, gc->repo);
    free(b.data);
    return -1;
  }
  if(b.len >= 2 && (unsigned char)b.data[0] == 0x1f && (unsigned char)b.data[1] == 0x8b) {
    Buffer d;
    memset(&d, 0, sizeof d);
    if(git_inflate_all((const unsigned char *)b.data, b.len, &d) == 0) {
      free(b.data);
      b = d;
    }
    else {
      free(d.data);
      snprintf(err, errsz, "failed to inflate info/refs");
      free(b.data);
      return -1;
    }
  }

  while(pos + 4 <= b.len) {
    unsigned long plen = 0;
    for(int pi = 0; pi < 4; pi++) {
      unsigned char c = b.data[pos + (size_t)pi];
      unsigned hv = (c >= '0' && c <= '9') ? c - '0' :
                    (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
                    (c >= 'A' && c <= 'F') ? c - 'A' + 10 : 16;
      if(hv == 16) break;
      plen = plen * 16 + hv;
    }
    if(plen == 0) {        /* flush pkt-line */
      pos += 4;
      continue;
    }
    if(plen < 4 || plen > (unsigned long)(b.len - pos))
      break;
    {
      size_t pay = (size_t)plen - 4;
      char *pl = b.data + pos + 4;
      size_t k = pay;
      if(k >= sizeof line) k = sizeof line - 1;
      memcpy(line, pl, k);
      line[k] = 0;
      pos += plen;
      if(!strncmp(line, "# service=", 10)) {
        if(!strncmp(line + 10, "git-upload-pack", 15))
          service_ok = 1;
        continue;
      }
      if(!service_ok)
        continue;
      {
        size_t nl = strlen(line);
        if(nl && line[nl-1] == '\n')
          line[--nl] = 0;
      }
      {
        char *z = memchr(line, '\0', sizeof line);
        size_t l0 = z ? (size_t)(z - line) : strlen(line);
        if(l0 >= 40 && line[40] == ' ') {
          unsigned char oid[20];
          char oidhex[41];
          const char *name = line + 41;
          const char *ne = name;
          while(*ne && *ne != ' ' && *ne != '\n')
            ne++;
          memcpy(oidhex, line, 40);
          oidhex[40] = 0;
          if(hex20(oidhex, oid) == 0) {
            size_t nlen = (size_t)(ne - name);
            if(gc->nrefs < (1 << 14)) {
              snprintf(gc->refs[gc->nrefs].name,
                       sizeof gc->refs[gc->nrefs].name, "%.*s",
                       (int)(nlen < 299 ? nlen : 299), name);
              memcpy(gc->refs[gc->nrefs].oid, oid, 20);
              gc->nrefs++;
            }
            {
              const char *cs = strstr(line + l0 + 1, "symref=");
              if(cs)
                snprintf(caps, sizeof caps, "%s", cs);
            }
            {
              const char *hs = strstr(caps, "symref=HEAD:");
              if(hs && !gc->have_head) {
                const char *bn = hs + strlen("symref=HEAD:");
                const char *be = bn;
                while(*be && *be != ' ' && *be != '\n' && *be != '\r')
                  be++;
                if(!strncmp(bn, "refs/heads/", 11))
                  bn += 11;
                snprintf(gc->branch, sizeof gc->branch, "%.*s",
                         (int)((size_t)(be - bn) < 299 ?
                               (size_t)(be - bn) : 299), bn);
                memcpy(gc->head_oid, oid, 20);
                gc->have_head = 1;
              }
            }
            if(!gc->have_head && nlen == 4 && !memcmp(name, "HEAD", 4)) {
              memcpy(gc->head_oid, oid, 20);
              gc->have_head = 1;
            }
          }
          if(gc->verbose) {
            char hexh[41];
            hex16(hexh, oid);
            fprintf(stderr, "volley clone: ref %.*s %s\n",
                    (int)((ne - name) < 299 ? (ne - name) : 299), name, hexh);
          }
        }
      }
    }
  }
  free(b.data);
  if(!service_ok) {
    snprintf(err, errsz, "not a smart http git repository: %s", gc->repo);
    return -1;
  }
  if(!gc->have_head) {
    snprintf(err, errsz, "no HEAD advertised by %s", gc->repo);
    return -1;
  }
  return 0;
}

static int git_fetch_pack(GClone *gc, Buffer *pb, char *err, size_t errsz)
{
  char url[4300];
  char want[64];
  char oidhex[41];
  char *body;
  size_t blen;
  int status = 0;

  snprintf(url, sizeof url, "%s/git-upload-pack", gc->repo);
  hex16(oidhex, gc->head_oid);
  snprintf(want, sizeof want, "want %s\n", oidhex);
  blen = strlen(want) + 4 + 17;
  body = malloc(blen + 1);
  if(!body)
    return -1;
  sprintf(body, "%04x%s00000009done\n0000",
          (unsigned)strlen(want) + 4, want);
  if(git_http(url, "POST", body, strlen(body),
              "application/x-git-upload-pack-request",
              "application/x-git-upload-pack-result",
              pb, &status, err, errsz) != 0) {
    free(body);
    return -1;
  }
  free(body);
  if(status >= 400) {
    snprintf(err, errsz, "upload-pack failed (status %d)", status);
    free(pb->data);
    return -1;
  }
  if(pb->len >= 2 && (unsigned char)pb->data[0] == 0x1f && (unsigned char)pb->data[1] == 0x8b) {
    Buffer d;
    memset(&d, 0, sizeof d);
    if(git_inflate_all((const unsigned char *)pb->data, pb->len, &d) == 0) {
      free(pb->data);
      *pb = d;
    }
    else {
      free(d.data);
      snprintf(err, errsz, "failed to inflate packfile");
      return -1;
    }
  }
  return 0;
}

static int git_parse_pack(Buffer *pb, GObj **objs, int *nobj,
                          char *err, size_t errsz)
{
  const unsigned char *p, *end;
  const unsigned char *pack = NULL;
  size_t i;
  unsigned int count;
  GObj *arr;

  if(pb->len < 12 + 32)
    return -1;
  for(i = 0; i + 8 < pb->len; i++) {
    if(pb->data[i] != 'P' || pb->data[i+1] != 'A' ||
       pb->data[i+2] != 'C' || pb->data[i+3] != 'K')
      continue;
    {
      unsigned int ver = ((unsigned int)(unsigned char)pb->data[i+4] << 24) |
                         ((unsigned int)(unsigned char)pb->data[i+5] << 16) |
                         ((unsigned int)(unsigned char)pb->data[i+6] << 8) |
                         (unsigned int)(unsigned char)pb->data[i+7];
      if(ver == 2 || ver == 3) {
        pack = (const unsigned char *)pb->data + i;
        break;
      }
    }
  }
  if(!pack) {
    snprintf(err, errsz, "no git packfile in upload-pack response");
    return -1;
  }
  count = ((unsigned int)pack[8] << 24) | ((unsigned int)pack[9] << 16) |
          ((unsigned int)pack[10] << 8) | (unsigned int)pack[11];
  if(count == 0 || count > (1u << 20)) {
    snprintf(err, errsz, "suspicious pack object count %u", count);
    return -1;
  }
  p = pack + 12;
  end = (const unsigned char *)pb->data + pb->len;
  arr = calloc((size_t)count, sizeof(GObj));
  if(!arr)
    return -1;
  for(unsigned int oi = 0; oi < count; oi++) {
    unsigned char hdr[32];
    unsigned char *in;
    long long size = 0;
    int type;
    int sh = 4;
    const unsigned char *q = p;
    if(q >= end) {
      snprintf(err, errsz, "truncated pack");
      free(arr);
      return -1;
    }
    hdr[0] = *q++;
    type = (hdr[0] >> 4) & 7;
    if(!type) {
      snprintf(err, errsz, "type 0 object in pack");
      free(arr);
      return -1;
    }
    size = hdr[0] & 15;
    while(hdr[0] & 0x80) {
      if(q >= end) {
        snprintf(err, errsz, "truncated pack object header");
        free(arr);
        return -1;
      }
      hdr[0] = *q++;
      size += (long long)(hdr[0] & 0x7f) << sh;
      sh += 7;
    }
    arr[oi].pack_off = (long long)(p - pack);
    arr[oi].type = type;
    arr[oi].size = size;
    if(type == 6 || type == 7) {
      if(type == 6) {
        unsigned long long off;
        if(q >= end) {
          snprintf(err, errsz, "bad ofs-delta");
          free(arr);
          return -1;
        }
        off = git_ofs(&q);
        arr[oi].base_off = arr[oi].pack_off - (long long)off;
        arr[oi].base_set = 1;
      }
      else {
        if((size_t)(end - q) < 20) {
          snprintf(err, errsz, "bad ref-delta");
          free(arr);
          return -1;
        }
        memcpy(arr[oi].base_oid, q, 20);
        q += 20;
      }
    }
    {
      unsigned char *in2;
      size_t consumed = 0;
      if(git_inflate_obj(q, (size_t)(end - q), size, &in2, &consumed) != 0) {
        snprintf(err, errsz, "object %u fails to inflate", oi);
        free(arr);
        return -1;
      }
      in = in2;
      p = q + consumed;
    }
    arr[oi].data = in;
    {
      char hdex[128];
      int hn;
      Buffer bf;
      unsigned char hh[20];
      memset(&bf, 0, sizeof bf);
      hn = snprintf(hdex, sizeof hdex, "%s %lld",
                    git_type_name(arr[oi].type), arr[oi].size);
      b_add(&bf, hdex, (size_t)hn);
      b_add(&bf, "", 1);
      b_add(&bf, (char *)in, (size_t)arr[oi].size);
      git_sha1((const unsigned char *)bf.data, bf.len, hh);
      memcpy(arr[oi].oid, hh, 20);
      if(arr[oi].type != 6 && arr[oi].type != 7)
        arr[oi].has_oid = 1;
      free(bf.data);
    }
    if(arr[oi].type != 6 && arr[oi].type != 7)
      arr[oi].resolved = 1;
  }
  *objs = arr;
  *nobj = (int)count;
  return 0;
}

static void git_reoid(GObj *o)
{
  char hdr[64], hdex[128];
  int hn;
  Buffer bf;
  unsigned char hh[20];
  hn = snprintf(hdr, sizeof hdr, "%s %lld", git_type_name(o->type), o->size);
  memset(&bf, 0, sizeof bf);
  snprintf(hdex, sizeof hdex, "%s", hdr);
  b_add(&bf, hdex, (size_t)hn);
  b_add(&bf, "", 1);
  b_add(&bf, (char *)o->data, (size_t)o->size);
  git_sha1((const unsigned char *)bf.data, bf.len, hh);
  memcpy(o->oid, hh, 20);
  o->has_oid = 1;
  free(bf.data);
}

static int git_resolve_deltas(GObj *arr, int count)
{
  int progress = 1;
  while(progress) {
    progress = 0;
    for(int i = 0; i < count; i++) {
      GObj *o = &arr[i];
      if(o->resolved)
        continue;
      if(o->type == 7) {
        for(int k = 0; k < count; k++) {
          if(!arr[k].resolved)
            continue;
          if(!memcmp(arr[k].oid, o->base_oid, 20)) {
            unsigned char *nd;
            size_t nl;
            if(git_apply_delta(arr[k].data, (size_t)arr[k].size,
                               o->data, (size_t)o->size, &nd, &nl) == 0) {
              free(o->data);
              o->data = nd;
              o->size = (long long)nl;
              o->type = arr[k].type;
              git_reoid(o);
              o->resolved = 1;
              progress = 1;
            }
            break;
          }
        }
      }
      else if(o->type == 6) {
        for(int k = 0; k < count; k++) {
          if(!arr[k].resolved)
            continue;
          if(arr[k].pack_off == o->base_off) {
            unsigned char *nd;
            size_t nl;
            if(git_apply_delta(arr[k].data, (size_t)arr[k].size,
                               o->data, (size_t)o->size, &nd, &nl) == 0) {
              free(o->data);
              o->data = nd;
              o->size = (long long)nl;
              o->type = arr[k].type;
              git_reoid(o);
              o->resolved = 1;
              progress = 1;
            }
            break;
          }
        }
      }
    }
  }
  for(int i = 0; i < count; i++)
    if((arr[i].type == 6 || arr[i].type == 7) && !arr[i].resolved) {
      if(g_verbose) {
        char dq[192];
        int ln;
        if(arr[i].type == 6)
          ln = snprintf(dq, sizeof dq,
                        "volley clone: unresolved ofs-delta (base_off=%lld)\n",
                        arr[i].base_off);
        else {
          char hx[41];
          hex16(hx, arr[i].base_oid);
          ln = snprintf(dq, sizeof dq, "volley clone: unresolved ref-delta (base=%s)\n", hx);
        }
        ssize_t wo = 0;
        while(wo < ln) {
          ssize_t w = write(2, dq + wo, (size_t)(ln - wo));
          if(w <= 0) break;
          wo += w;
        }
      }
      return -1;
    }
  return 0;
}

static int git_write_all(const char *path, const unsigned char *data, size_t n,
                         char *err, size_t errsz)
{
  FILE *f = fopen(path, "wb");
  if(!f) {
    snprintf(err, errsz, "cannot write %s: %s", path, strerror(errno));
    return -1;
  }
  if(n && fwrite(data, 1, n, f) != n) {
    snprintf(err, errsz, "short write to %s: %s", path, strerror(errno));
    fclose(f);
    return -1;
  }
  fclose(f);
  return 0;
}

static int git_mkdir_p(const char *path)
{
  char tmp[4096];
  size_t n = strlen(path);
  if(n >= sizeof tmp)
    return -1;
  memcpy(tmp, path, n + 1);
  for(char *pp = tmp + 1; *pp; pp++) {
    if(*pp == '/') {
      *pp = 0;
      mkdir(tmp, 0755);
      *pp = '/';
    }
  }
  return mkdir(tmp, 0755) == 0 || errno == EEXIST ? 0 : -1;
}

static int git_write_loose(const char *gitdir, const GObj *o,
                           char *err, size_t errsz)
{
  char hdr[64], dir[4200], path[4200];
  char *body;
  int hn;
  uLongf clen;
  unsigned char *cbuf;
  int r = -1;
  unsigned char ohex[41];
  hex16((char *)ohex, o->oid);
  snprintf(dir, sizeof dir, "%s/objects/%c%c", gitdir, ohex[0], ohex[1]);
  snprintf(path, sizeof path, "%s/%s", dir, ohex + 2);
  if(access(path, F_OK) == 0)
    return 0;
  git_mkdir_p(dir);
  hn = snprintf(hdr, sizeof hdr, "%s %lld", git_type_name(o->type), o->size);
  body = malloc((size_t)hn + 1 + (size_t)o->size);
  if(!body)
    return -1;
  memcpy(body, hdr, (size_t)hn);
  body[hn] = 0;
  memcpy(body + hn + 1, o->data, (size_t)o->size);
  clen = compressBound((uLong)(hn + 1 + o->size));
  cbuf = malloc(clen);
  if(cbuf && compress2(cbuf, &clen, (const Bytef *)body,
                       (uLong)(hn + 1 + o->size), Z_BEST_SPEED) == Z_OK)
    r = git_write_all(path, cbuf, clen, err, errsz);
  free(cbuf);
  free(body);
  return r;
}

static int git_write_refs(GClone *gc, const char *gitdir,
                          GObj *objs, int nobj,
                          char *err, size_t errsz)
{
  char path[4200], ohex[41], line[64];
  snprintf(path, sizeof path, "%s/HEAD", gitdir);
  if(gc->branch[0])
    snprintf(line, sizeof line, "ref: refs/heads/%s\n", gc->branch);
  else
    snprintf(line, sizeof line, "ref: refs/heads/master\n");
  if(git_write_all(path, (const unsigned char *)line, strlen(line), err, errsz) != 0)
    return -1;
  for(int i = 0; i < gc->nrefs; i++) {
    const char *nm = gc->refs[i].name;
    int present = 0;
    for(int j = 0; j < nobj; j++)
      if(objs[j].has_oid && !memcmp(objs[j].oid, gc->refs[i].oid, 20)) {
        present = 1;
        break;
      }
    if(!present)
      continue;
    if(!strcmp(nm, "HEAD"))
      continue;
    if(strncmp(nm, "refs/", 5))
      continue;
    if(strstr(nm, "^{}"))
      continue;
    hex16(ohex, gc->refs[i].oid);
    snprintf(path, sizeof path, "%s/%s", gitdir, nm);
    if(strlen(path) >= sizeof path - 40)
      continue;
    {
      char *slash = strrchr(path, '/');
      if(slash) {
        *slash = 0;
        git_mkdir_p(path);
        *slash = '/';
      }
    }
    snprintf(line, sizeof line, "%s\n", ohex);
    if(git_write_all(path, (const unsigned char *)line, strlen(line), err, errsz) != 0)
      return -1;
  }
  if(gc->branch[0] && gc->have_head) {
    snprintf(path, sizeof path, "%s/refs/heads/%s", gitdir, gc->branch);
    {
      char *slash = strrchr(path, '/');
      if(slash) {
        *slash = 0;
        git_mkdir_p(path);
        *slash = '/';
      }
    }
    hex16(ohex, gc->head_oid);
    snprintf(line, sizeof line, "%s\n", ohex);
    if(git_write_all(path, (const unsigned char *)line, strlen(line), err, errsz) != 0)
      return -1;
  }
  return 0;
}

static int git_write_config(const char *gitdir, const char *url,
                            int bare, char *err, size_t errsz)
{
  char path[4200], conf[4096];
  snprintf(path, sizeof path, "%s/config", gitdir);
  snprintf(conf, sizeof conf,
    "[core]\n"
    "\trepositoryformatversion = 0\n"
    "\tfilemode = true\n"
    "\tbare = %s\n"
    "\tlogallrefupdates = true\n"
    "[remote \"origin\"]\n"
    "\turl = %s\n"
    "\tfetch = +refs/heads/*:refs/remotes/origin/*\n",
    bare ? "true" : "false", url);
  return git_write_all(path, (const unsigned char *)conf, strlen(conf), err, errsz);
}

static GObj *git_find(GObj *arr, int count, const unsigned char *oid)
{
  for(int i = 0; i < count; i++)
    if(arr[i].has_oid && !memcmp(arr[i].oid, oid, 20))
      return &arr[i];
  return NULL;
}

static int git_checkout_tree(GObj *arr, int count, GObj *t,
                             const char *path, char *err, size_t errsz)
{
  const unsigned char *p = (const unsigned char *)t->data;
  const unsigned char *end = (const unsigned char *)t->data + t->size;
  while(p < end) {
    const unsigned char *sp = p;
    while(p < end && *p != ' ')
      p++;
    if(p >= end)
      break;
    {
      char mode[16];
      size_t ml = (size_t)(p - sp);
      if(ml >= sizeof mode) ml = sizeof mode - 1;
      memcpy(mode, sp, ml);
      mode[ml] = 0;
      p++;
      {
        const unsigned char *n0 = p;
        while(p < end && *p != 0)
          p++;
        if(p >= end)
          break;
        {
          size_t nl = (size_t)(p - n0);
          char name[256];
          const unsigned char *oid = p + 1;
          if(nl >= sizeof name) nl = sizeof name - 1;
          if(nl == 0) {
            p = end;
            break;
          }
          memcpy(name, n0, nl);
          name[nl] = 0;
          p = oid + 20;
          if(strchr(name, '/') || (nl == 2 && name[0] == '.' && name[1] == '.'))
            continue;
          if(!strcmp(mode, "40000") || !strcmp(mode, "040000")) {
            char sub[4200];
            GObj *o = git_find(arr, count, oid);
            snprintf(sub, sizeof sub, "%s/%s", path, name);
            git_mkdir_p(sub);
            if(o && o->type == 2)
              git_checkout_tree(arr, count, o, sub, err, errsz);
          }
          else if(!strcmp(mode, "160000")) {
            char sub[4200];
            snprintf(sub, sizeof sub, "%s/%s", path, name);
            git_mkdir_p(sub);
          }
          else {
            char fp[4200];
            GObj *o = git_find(arr, count, oid);
            snprintf(fp, sizeof fp, "%s/%s", path, name);
            if(!o || o->type != 3) {
              snprintf(err, errsz, "missing blob for %s", fp);
              return -1;
            }
            if(git_write_all(fp, o->data, (size_t)o->size, err, errsz) != 0)
              return -1;
            chmod(fp, strcmp(mode, "100755") ? 0644 : 0755);
            if(!strcmp(mode, "120000")) {
              unsigned char *s = malloc((size_t)o->size + 1);
              if(s) {
                memcpy(s, o->data, (size_t)o->size);
                s[o->size] = 0;
                unlink(fp);
                symlink((const char *)s, fp);
                free(s);
              }
            }
          }
        }
      }
    }
  }
  return 0;
}

static int git_checkout(GObj *arr, int count, const unsigned char *tree,
                        const char *path, char *err, size_t errsz)
{
  GObj *t = git_find(arr, count, tree);
  if(!t || t->type != 2) {
    snprintf(err, errsz, "root tree object not found");
    return -1;
  }
  git_mkdir_p(path);
  return git_checkout_tree(arr, count, t, path, err, errsz);
}

typedef struct {
  char name[900];
  unsigned int mode;
  unsigned char oid[20];
} IEntry;

static unsigned int git_index_mode(const char *mode)
{
  if(!strcmp(mode, "100755"))
    return 0x81ED;
  if(!strcmp(mode, "120000"))
    return 0xA000;
  if(!strcmp(mode, "160000"))
    return 0xE000;
  return 0x81A4;
}

static int git_collect_index(GObj *arr, int count, GObj *t,
                             const char *base, IEntry *ie, int *nie)
{
  const unsigned char *p = (const unsigned char *)t->data;
  const unsigned char *end = (const unsigned char *)t->data + t->size;
  while(p < end) {
    const unsigned char *sp = p;
    while(p < end && *p != ' ')
      p++;
    if(p >= end)
      break;
    {
      char mode[16];
      size_t ml = (size_t)(p - sp);
      if(ml >= sizeof mode) ml = sizeof mode - 1;
      memcpy(mode, sp, ml);
      mode[ml] = 0;
      p++;
      {
        const unsigned char *n0 = p;
        while(p < end && *p != 0)
          p++;
        if(p >= end)
          break;
        {
          size_t nl = (size_t)(p - n0);
          const unsigned char *oid = p + 1;
          p = oid + 20;
          if(!strcmp(mode, "40000") || !strcmp(mode, "040000")) {
            char sub[4200];
            GObj *o = git_find(arr, count, oid);
            snprintf(sub, sizeof sub, "%s%.*s/", base, (int)nl, n0);
            if(o && o->type == 2)
              git_collect_index(arr, count, o, sub, ie, nie);
            continue;
          }
          if(nl == 0 || (nl == 2 && n0[0] == '.' && n0[1] == '.'))
            continue;
          if(*nie >= (1 << 14))
            continue;
          {
            IEntry *e = &ie[*nie];
            snprintf(e->name, sizeof e->name, "%s%.*s",
                     base, (int)nl, n0);
            e->mode = git_index_mode(mode);
            memcpy(e->oid, oid, 20);
            (*nie)++;
          }
        }
      }
    }
  }
  return 0;
}

static void git_wbe32(unsigned char *p, unsigned int v)
{
  p[0] = (unsigned char)(v >> 24);
  p[1] = (unsigned char)(v >> 16);
  p[2] = (unsigned char)(v >> 8);
  p[3] = (unsigned char)v;
}

static int git_write_index(const char *gitdir, IEntry *ie, int nie,
                           char *err, size_t errsz)
{
  Buffer b;
  size_t i;
  unsigned char trailer[20];
  char path[4200];
  int swapped = 1;

  while(swapped) {
    swapped = 0;
    for(i = 1; i < (size_t)nie; i++) {
      if(strcmp(ie[i-1].name, ie[i].name) > 0) {
        IEntry t = ie[i-1];
        ie[i-1] = ie[i];
        ie[i] = t;
        swapped = 1;
      }
    }
  }
  memset(&b, 0, sizeof b);
  b_add(&b, "DIRC", 4);
  {
    unsigned char c[8];
    git_wbe32(c, 2);
    git_wbe32(c + 4, (unsigned int)nie);
    b_add(&b, (const char *)c, 8);
  }
  for(i = 0; i < (size_t)nie; i++) {
    unsigned char e[62];
    size_t nl = strlen(ie[i].name);
    unsigned int fl = (unsigned int)(nl < 0xFFF ? nl : 0xFFF);
    unsigned char fc[2];
    size_t tot, pad;
    memset(e, 0, sizeof e);
    git_wbe32(e, 0);            /* ctime sec */
    git_wbe32(e + 4, 0);        /* ctime nsec */
    git_wbe32(e + 8, 0);        /* mtime sec: */
    git_wbe32(e + 12, 0);
    git_wbe32(e + 16, 0);       /* dev */
    git_wbe32(e + 20, 0);       /* ino */
    git_wbe32(e + 24, ie[i].mode);   /* mode */
    git_wbe32(e + 28, 0);       /* uid */
    git_wbe32(e + 32, 0);       /* gid */
    git_wbe32(e + 36, 0);       /* size */
    b_add(&b, (const char *)e, 40);
    b_add(&b, (const char *)ie[i].oid, 20);
    fc[0] = (unsigned char)(fl >> 8);
    fc[1] = (unsigned char)fl;
    b_add(&b, (const char *)fc, 2);
    b_add(&b, (const char *)ie[i].name, nl);
    b_add(&b, "", 1);
    tot = 40 + 20 + 2 + nl + 1;
    pad = ((62 + nl + 8) & ~7) - tot;
    {
      char z[8] = {0,0,0,0,0,0,0,0};
      b_add(&b, z, pad);
    }
    }
  git_sha1((const unsigned char *)b.data, b.len, trailer);
  b_add(&b, (const char *)trailer, 20);
  snprintf(path, sizeof path, "%s/index", gitdir);
  if(git_write_all(path, (const unsigned char *)b.data, b.len, err, errsz) != 0) {
    free(b.data);
    return -1;
  }
  free(b.data);
  return 0;
}

static int git_default_dir(const char *url, char *out, size_t cap)
{
  const char *p = url;
  const char *last = NULL;
  while(*p) {
    if(*p == '/')
      last = p;
    p++;
  }
  if(last)
    snprintf(out, cap, "%s", last + 1);
  else
    snprintf(out, cap, "%s", url);
  {
    size_t n = strlen(out);
    if(n > 4 && !strcmp(out + n - 4, ".git"))
      out[n - 4] = 0;
  }
  return 0;
}

static int git_clone_impl(const char *url, const char *dest,
                          const struct volley_git_opts *o,
                          char *err, size_t errsz)
{
  GClone gc;
  Buffer pb;
  GObj *objs = NULL;
  int nobj = 0;
  char gitdir[4200];
  GObj *head_commit = NULL;
  unsigned char root_tree[20] = {0};
  int have_tree = 0;

  memset(&gc, 0, sizeof gc);
  snprintf(gc.repo, sizeof gc.repo, "%s", url);
  while(gc.repo[0] && gc.repo[strlen(gc.repo) - 1] == '/')
    gc.repo[strlen(gc.repo) - 1] = 0;
  gc.verbose = o ? o->verbose : 0;
  gc.quiet = o ? o->quiet : 0;
  gc.bare = o ? o->bare : 0;
  if(gc.verbose)
    g_verbose = 1;
  gc.refs = calloc(1 << 14, sizeof(GRef));
  if(!gc.refs) {
    snprintf(err, errsz, "out of memory");
    return -1;
  }

  if(git_fetch_refs(&gc, err, errsz) != 0)
    goto done;
  if(git_fetch_pack(&gc, &pb, err, errsz) != 0)
    goto done;
  if(git_parse_pack(&pb, &objs, &nobj, err, errsz) != 0) {
    free(pb.data);
    goto done;
  }
  free(pb.data);
  if(git_resolve_deltas(objs, nobj) != 0) {
    snprintf(err, errsz, "failed to resolve pack deltas");
    goto done;
  }
  for(int i = 0; i < nobj; i++)
    if(objs[i].has_oid && objs[i].type == 1 &&
       !memcmp(objs[i].oid, gc.head_oid, 20))
      head_commit = &objs[i];
  if(gc.verbose)
    fprintf(stderr, "volley clone: %d objects in packfile\n", nobj);
  if(head_commit) {
    const unsigned char *p = head_commit->data;
    const unsigned char *end = head_commit->data + head_commit->size;
    while(p < end) {
      const unsigned char *sp = p;
      while(p < end && *p != '\n')
        p++;
      if(p >= end)
        break;
      p++;
      if(!strncmp((const char *)sp, "tree ", 5)) {
        if(p >= sp + 5 + 40) {
          char th[41];
          memcpy(th, sp + 5, 40);
          th[40] = 0;
          if(hex20(th, root_tree) == 0)
            have_tree = 1;
        }
      }
    }
  }

  if(gc.bare) {
    snprintf(gitdir, sizeof gitdir, "%s", dest);
  }
  else {
    snprintf(gitdir, sizeof gitdir, "%s/.git", dest);
  }
  git_mkdir_p(gitdir);
  for(int i = 0; i < nobj; i++)
    if(git_write_loose(gitdir, &objs[i], err, errsz) != 0)
      goto done;
  if(git_write_config(gitdir, url, gc.bare, err, errsz) != 0)
    goto done;
  if(git_write_refs(&gc, gitdir, objs, nobj, err, errsz) != 0)
    goto done;

  if(!gc.bare && have_tree) {
    if(git_checkout(objs, nobj, root_tree, dest, err, errsz) != 0)
      goto done;
    {
      IEntry *ie = calloc((size_t)nobj + 16, sizeof(IEntry));
      int nie = 0;
      GObj *rt = git_find(objs, nobj, root_tree);
      if(ie && rt) {
        git_collect_index(objs, nobj, rt, "", ie, &nie);
        if(nie > 0)
          git_write_index(gitdir, ie, nie, err, errsz);
      }
      free(ie);
    }
  }

  if(!gc.quiet) {
    const char *branch = gc.branch[0] ? gc.branch : "master";
    fprintf(stdout, "done. cloned %s into %s (%d objects, branch %s)\n",
            url, dest, nobj, branch);
  }
  free(gc.refs);
  for(int i = 0; i < nobj; i++)
    free(objs[i].data);
  free(objs);
  return 0;
done:
  free(gc.refs);
  if(objs) {
    for(int i = 0; i < nobj; i++)
      free(objs[i].data);
    free(objs);
  }
  return -1;
}

#ifndef VOLLEY_LIB
/* ------------------------------------------------------------------ */
/* git porcelain-lite: local repo reading + subcommands (CLI only)     */
/* ------------------------------------------------------------------ */
typedef struct {
  char gitdir[4096];
} GRepo;

static int git_file_read(const char *path, unsigned char **out, size_t *outn)
{
  FILE *f;
  long sz;
  unsigned char *d;
  f = fopen(path, "rb");
  if(!f)
    return -1;
  if(fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0) {
    fclose(f);
    return -1;
  }
  rewind(f);
  d = malloc((size_t)sz + 1);
  if(!d) {
    fclose(f);
    return -1;
  }
  if(sz && fread(d, 1, (size_t)sz, f) != (size_t)sz) {
    free(d);
    fclose(f);
    return -1;
  }
  fclose(f);
  d[sz] = 0;
  *out = d;
  *outn = (size_t)sz;
  return 0;
}

static int git_repo_open(int argc, char **argv, int *k,
                         char *gitdir, size_t gitcap,
                         char *err, size_t errsz)
{
  const char *cd = ".";
  const char *gd = NULL;
  int i = *k;
  while(i < argc && (argv[i][0] == '-' && argv[i][1])) {
    if(!strcmp(argv[i], "-C")) {
      if(i + 1 >= argc) {
        snprintf(err, errsz, "option -C needs a path argument");
        return -1;
      }
      cd = argv[i + 1];
      i += 2;
    }
    else if(!strcmp(argv[i], "--git-dir")) {
      if(i + 1 >= argc) {
        snprintf(err, errsz, "option --git-dir needs a path argument");
        return -1;
      }
      gd = argv[i + 1];
      i += 2;
    }
    else
      break;
  }
  *k = i;
  if(gd) {
    snprintf(gitdir, gitcap, "%s", gd);
  }
  else {
    size_t n = strlen(cd);
    while(n && cd[n - 1] == '/')
      n--;
    if(n == 0) {
      snprintf(gitdir, gitcap, ".git");
    }
    else if(n + 6 <= gitcap) {
      memcpy(gitdir, cd, n);
      memcpy(gitdir + n, "/.git", 6);
    }
    else {
      return -1;
    }
  }
  {
    size_t m = strlen(gitdir);
    while(m > 1 && gitdir[m - 1] == '/')
      gitdir[--m] = 0;
  }
  if(access(gitdir, F_OK) != 0) {
    snprintf(err, errsz, "not a git repository: %s", gitdir);
    return -1;
  }
  return 0;
}

static int git_hex40(const char *s, unsigned char *out)
{
  for(int i = 0; i < 20; i++) {
    int a = unhex1(s[i * 2]);
    int b = unhex1(s[i * 2 + 1]);
    if(a < 0 || b < 0)
      return -1;
    out[i] = (unsigned char)((a << 4) | b);
  }
  return 0;
}

static int git_parse_ref_file(const unsigned char *d, size_t n, unsigned char *oid)
{
  size_t k = 0;
  while(k < n && (d[k] == ' ' || d[k] == '\t' || d[k] == '\n' || d[k] == '\r'))
    k++;
  if(k + 40 > n)
    return -1;
  return git_hex40((const char *)d + k, oid);
}

static int git_packed_find(GRepo *r, const char *name, unsigned char *oid)
{
  char path[4200];
  unsigned char *d;
  size_t n, pos = 0;
  int found = -1;
  snprintf(path, sizeof path, "%s/packed-refs", r->gitdir);
  if(git_file_read(path, &d, &n) != 0)
    return -1;
  while(pos < n) {
    size_t e = pos;
    while(e < n && d[e] != '\n')
      e++;
    if(d[pos] == '#' || d[pos] == '^') {
      pos = e + 1;
      continue;
    }
    if(e - pos > 40 && d[pos + 40] == ' ') {
      unsigned char o[20];
      if(git_hex40((const char *)d + pos, o) == 0) {
        const char *nm = (const char *)d + pos + 41;
        size_t nl = e - pos - 41;
        if(nl == strlen(name) && !memcmp(nm, name, nl)) {
          memcpy(oid, o, 20);
          found = 0;
          break;
        }
      }
    }
    pos = e + 1;
  }
  free(d);
  return found;
}

static int git_resolve_name(GRepo *r, const char *name, unsigned char *oid)
{
  char cand[4][4200];
  int nc = 0;
  char path[4200];
  unsigned char *d;
  size_t n;
  int i;
  if(!strcmp(name, "HEAD")) {
    snprintf(path, sizeof path, "%s/HEAD", r->gitdir);
    if(git_file_read(path, &d, &n) != 0)
      return -1;
    if(n > 5 && !memcmp(d, "ref: ", 5)) {
      size_t s = 5;
      char sub[400];
      while(s < n && d[s] && d[s] != '\n' && d[s] != '\r')
        s++;
      {
        size_t sl = s - 5;
        if(sl >= sizeof sub)
          sl = sizeof sub - 1;
        memcpy(sub, d + 5, sl);
        sub[sl] = 0;
      }
      free(d);
      return git_resolve_name(r, sub, oid);
    }
    else {
      int rc = git_parse_ref_file(d, n, oid);
      free(d);
      return rc;
    }
  }
  snprintf(cand[nc], sizeof cand[nc], "%s", name);
  nc++;
  if(strncmp(name, "refs/", 5)) {
    snprintf(cand[nc], sizeof cand[nc], "refs/heads/%s", name);
    nc++;
    snprintf(cand[nc], sizeof cand[nc], "refs/tags/%s", name);
    nc++;
    snprintf(cand[nc], sizeof cand[nc], "refs/remotes/%s", name);
    nc++;
  }
  for(i = 0; i < nc; i++) {
    snprintf(path, sizeof path, "%s/%s", r->gitdir, cand[i]);
    if(git_file_read(path, &d, &n) == 0) {
      int rc = git_parse_ref_file(d, n, oid);
      free(d);
      if(rc == 0)
        return 0;
    }
  }
  for(i = 0; i < nc; i++)
    if(git_packed_find(r, cand[i], oid) == 0)
      return 0;
  return -1;
}

static int git_resolve_thing(GRepo *r, const char *thing, unsigned char *oid,
                             char *err, size_t errsz)
{
  if(strlen(thing) == 40 && hex20(thing, oid) == 0)
    return 0;
  if(git_resolve_name(r, thing, oid) == 0)
    return 0;
  snprintf(err, errsz, "unknown ref or object: %s", thing);
  return -1;
}

static GObj *git_read_obj(GRepo *r, const unsigned char *oid, GObj *out,
                          char *err, size_t errsz)
{
  char hex[41], path[4200];
  unsigned char *d;
  size_t n, hz = 0;
  long long size = 0;
  int type = 0;
  Buffer rb;
  GObj *res = NULL;
  hex16(hex, oid);
  snprintf(path, sizeof path, "%s/objects/%c%c/%s", r->gitdir,
           hex[0], hex[1], hex + 2);
  if(git_file_read(path, &d, &n) != 0) {
    snprintf(err, errsz, "object %s not found", hex);
    return NULL;
  }
  memset(&rb, 0, sizeof rb);
  if(git_inflate_all(d, n, &rb) != 0) {
    free(d);
    free(rb.data);
    snprintf(err, errsz, "object %s fails to inflate", hex);
    return NULL;
  }
  free(d);
  while(hz < rb.len && rb.data[hz] != 0)
    hz++;
  if(hz < 5 || hz >= rb.len) {
    snprintf(err, errsz, "corrupt loose object %s", hex);
    goto out;
  }
  {
    char hdr[64];
    size_t hl = hz;
    char *sp;
    char *endp;
    if(hl >= sizeof hdr)
      hl = sizeof hdr - 1;
    memcpy(hdr, rb.data, hl);
    hdr[hl] = 0;
    sp = memchr(hdr, ' ', hl);
    if(!sp) {
      snprintf(err, errsz, "corrupt loose object %s", hex);
      goto out;
    }
    *sp = 0;
    if(!strcmp(hdr, "commit")) type = 1;
    else if(!strcmp(hdr, "tree")) type = 2;
    else if(!strcmp(hdr, "blob")) type = 3;
    else if(!strcmp(hdr, "tag")) type = 4;
    else {
      snprintf(err, errsz, "unknown object type '%s' in %s", hdr, hex);
      goto out;
    }
    size = strtoll(sp + 1, &endp, 10);
    if(endp == sp + 1 || (*endp && *endp != '\0') || size < 0) {
      snprintf(err, errsz, "corrupt loose object %s", hex);
      goto out;
    }
  }
  if((long long)(rb.len - hz - 1) != size) {
    snprintf(err, errsz, "size mismatch in %s (%lld != %lld)", hex,
             (long long)(rb.len - hz - 1), size);
    goto out;
  }
  memset(out, 0, sizeof *out);
  out->data = malloc((size_t)size + 1);
  if(!out->data)
    goto out;
  memcpy(out->data, rb.data + hz + 1, (size_t)size);
  out->data[size] = 0;
  memcpy(out->oid, oid, 20);
  out->has_oid = 1;
  out->type = type;
  out->size = size;
  out->resolved = 1;
  res = out;
out:
  free(rb.data);
  return res;
}

typedef int (*git_ref_cb)(GRepo *r, const char *name, const unsigned char *oid,
                          void *ctx);

static int git_walk_dir(GRepo *r, const char *dirpath, const char *prefix,
                        git_ref_cb cb, void *ctx)
{
  DIR *d;
  struct dirent *e;
  struct stat st;
  d = opendir(dirpath);
  if(!d)
    return 0;
  while((e = readdir(d))) {
    char path[4300], name[360], ref[360];
    unsigned char oid[20];
    unsigned char *buf;
    size_t n;
    if(!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..") ||
       !strcmp(e->d_name, "packed-refs"))
      continue;
    snprintf(path, sizeof path, "%s/%s", dirpath, e->d_name);
    if(stat(path, &st) != 0)
      continue;
    if(S_ISDIR(st.st_mode)) {
      snprintf(name, sizeof name, "%s%s%s", prefix, prefix[0] ? "/" : "", e->d_name);
      git_walk_dir(r, path, name, cb, ctx);
      continue;
    }
    if(git_file_read(path, &buf, &n) != 0)
      continue;
    if(git_parse_ref_file(buf, n, oid) != 0) {
      free(buf);
      continue;
    }
    free(buf);
    snprintf(ref, sizeof ref, "%s%s%s", prefix, prefix[0] ? "/" : "", e->d_name);
    if(cb)
      cb(r, ref, oid, ctx);
  }
  closedir(d);
  return 0;
}

static int git_packed_list(GRepo *r, const char *prefix, git_ref_cb cb, void *ctx)
{
  char path[4200];
  unsigned char *d;
  size_t n, pos = 0, pl = strlen(prefix);
  snprintf(path, sizeof path, "%s/packed-refs", r->gitdir);
  if(git_file_read(path, &d, &n) != 0)
    return 0;
  while(pos < n) {
    size_t e = pos;
    while(e < n && d[e] != '\n')
      e++;
    if(d[pos] != '#' && d[pos] != '^' && e - pos > 40 && d[pos + 40] == ' ') {
      unsigned char o[20];
      if(git_hex40((const char *)d + pos, o) == 0) {
        size_t nl = e - pos - 41;
        if(nl > pl && !memcmp(d + pos + 41, prefix, pl) && d[pos + 41 + pl] == '/') {
          char nm[400];
          if(nl >= sizeof nm)
            nl = sizeof nm - 1;
          memcpy(nm, d + pos + 41, nl);
          nm[nl] = 0;
          if(cb)
            cb(r, nm, o, ctx);
        }
      }
    }
    pos = e + 1;
  }
  free(d);
  return 0;
}

typedef struct {
  GRef *refs;
  int n;
  int cap;
} RefSet;

static void refset_add(RefSet *s, const char *name, const unsigned char *oid)
{
  int i;
  for(i = 0; i < s->n; i++)
    if(!strcmp(s->refs[i].name, name))
      return;
  if(s->n + 1 > s->cap) {
    int ncap = s->cap ? s->cap * 2 : 16;
    GRef *nr = realloc(s->refs, (size_t)ncap * sizeof(GRef));
    if(!nr)
      return;
    s->refs = nr;
    s->cap = ncap;
  }
  snprintf(s->refs[s->n].name, sizeof s->refs[s->n].name, "%s", name);
  memcpy(s->refs[s->n].oid, oid, 20);
  s->n++;
}

static int refset_add_cb(GRepo *r, const char *name, const unsigned char *oid,
                         void *ctx)
{
  (void)r;
  refset_add((RefSet *)ctx, name, oid);
  return 0;
}

static void git_collect(GRepo *r, const char *dir, const char *prefix, RefSet *set)
{
  char dp[4200];
  snprintf(dp, sizeof dp, "%s/%s", r->gitdir, dir);
  git_walk_dir(r, dp, prefix, refset_add_cb, set);
  git_packed_list(r, prefix, refset_add_cb, set);
}

static void refset_sort(RefSet *s)
{
  for(int i = 0; i < s->n; i++)
    for(int j = i + 1; j < s->n; j++)
      if(strcmp(s->refs[j].name, s->refs[i].name) < 0) {
        GRef t = s->refs[i];
        s->refs[i] = s->refs[j];
        s->refs[j] = t;
      }
}

static void git_tree_pretty(const GObj *t, FILE *fp)
{
  const unsigned char *p = (const unsigned char *)t->data;
  const unsigned char *end = p + t->size;
  while(p < end) {
    const unsigned char *sp = p;
    while(p < end && *p != ' ')
      p++;
    if(p >= end)
      break;
    {
      char ms[16];
      size_t ml = (size_t)(p - sp);
      if(ml >= sizeof ms)
        ml = sizeof ms - 1;
      memcpy(ms, sp, ml);
      ms[ml] = 0;
      p++;
      {
        const unsigned char *n0 = p;
        while(p < end && *p != 0)
          p++;
        if(p >= end)
          break;
        {
          size_t nl = (size_t)(p - n0);
          char name[256];
          const unsigned char *oidp = p + 1;
          char ohex[41];
          const char *kind;
          if(nl >= sizeof name)
            nl = sizeof name - 1;
          memcpy(name, n0, nl);
          name[nl] = 0;
          hex16(ohex, oidp);
          if(!strcmp(ms, "40000") || !strcmp(ms, "040000"))
            kind = "tree";
          else if(!strcmp(ms, "160000"))
            kind = "commit";
          else
            kind = "blob";
          fprintf(fp, "%s %s %s\t%s\n", ms, kind, ohex, name);
          p = oidp + 20;
        }
      }
    }
  }
}

static int git_treeish(GRepo *r, const unsigned char *start, unsigned char *treeoid,
                       GObj *out, char *err, size_t errsz)
{
  unsigned char oid[20];
  int found;
  memcpy(oid, start, 20);
  for(int hop = 0; hop < 8; hop++) {
    GObj o;
    if(!git_read_obj(r, oid, &o, err, errsz))
      return -1;
    if(o.type == 2) {
      memcpy(treeoid, oid, 20);
      memcpy(out, &o, sizeof *out);
      return 0;
    }
    if(o.type == 1 || o.type == 4) {
      const unsigned char *p = o.data, *e = o.data + o.size;
      const char *tag = (o.type == 1) ? "tree " : "object ";
      int tl = (o.type == 1) ? 45 : 47;
      found = 0;
      while(p < e) {
        const unsigned char *ln = p;
        while(p < e && *p != '\n')
          p++;
        if((size_t)(p - ln) >= (size_t)tl &&
           !memcmp(ln, tag, (o.type == 1) ? 5 : 7)) {
          if(git_hex40((const char *)ln + ((o.type == 1) ? 5 : 7), oid) == 0)
            found = 1;
          break;
        }
        if(p < e)
          p++;
      }
      free(o.data);
      if(!found) {
        snprintf(err, errsz, "%s object has no %s", git_type_name(o.type),
                 o.type == 1 ? "tree" : "target");
        return -1;
      }
      continue;
    }
    free(o.data);
    break;
  }
  snprintf(err, errsz, "object is not a treeish");
  return -1;
}

typedef struct {
  char name[128];
  char url[1200];
} Rmt;

static int git_remote_list(const char *cfg, Rmt *rmts, int cap, int *nrmt)
{
  unsigned char *d;
  size_t n, pos = 0;
  int cur = -1;
  *nrmt = 0;
  if(git_file_read(cfg, &d, &n) != 0)
    return 0;
  while(pos < n) {
    size_t e = pos;
    while(e < n && d[e] != '\n')
      e++;
    if(e - pos) {
      size_t ln = e - pos;
      if(d[e - 1] == '\r')
        ln--;
      if(ln) {
        char line[1600];
        if(ln >= sizeof line)
          ln = sizeof line - 1;
        memcpy(line, d + pos, ln);
        line[ln] = 0;
        {
          size_t a = 0;
          while(a < ln && (line[a] == ' ' || line[a] == '\t'))
            a++;
          if(line[a] == '[' && ln > a + 1 && line[ln - 1] == ']') {
            line[ln - 1] = 0;
            if(!strncmp(line + a + 1, "remote \"", 8)) {
              const char *nm = line + a + 9;
              char *q = strchr(nm, '"');
              if(q) {
                *q = 0;
                if(*nrmt < cap) {
                  snprintf(rmts[*nrmt].name, sizeof rmts[*nrmt].name, "%s", nm);
                  rmts[*nrmt].url[0] = 0;
                  cur = *nrmt;
                  (*nrmt)++;
                }
                else
                  cur = -1;
              }
              else
                cur = -1;
            }
            else
              cur = -1;
          }
          else if(cur >= 0) {
            char *eq = strchr(line + a, '=');
            if(eq) {
              char key[64];
              size_t kl = (size_t)(eq - (line + a));
              const char *val;
              if(kl >= sizeof key)
                kl = sizeof key - 1;
              memcpy(key, line + a, kl);
              key[kl] = 0;
              while(kl && (key[kl - 1] == ' ' || key[kl - 1] == '\t'))
                key[--kl] = 0;
              val = eq + 1;
              while(*val == ' ' || *val == '\t')
                val++;
              if(!strcmp(key, "url") && !rmts[cur].url[0]) {
                snprintf(rmts[cur].url, sizeof rmts[cur].url, "%s", val);
              }
            }
          }
        }
      }
    }
    pos = e + 1;
  }
  free(d);
  return 0;
}

static int git_argv_is_cmd(const char *s)
{
  return !strcmp(s, "clone")     || !strcmp(s, "ls-remote") ||
         !strcmp(s, "branch")    || !strcmp(s, "tag")       ||
         !strcmp(s, "remote")    || !strcmp(s, "rev-parse") ||
         !strcmp(s, "cat-file")  || !strcmp(s, "log")       ||
         !strcmp(s, "ls-tree")   || !strcmp(s, "init");
}

static int cmd_git_ls_remote(int argc, char **argv)
{
  const char *url = NULL;
  const char **pats = NULL;
  int npats = 0, cpats = 0;
  char err[1024];
  GClone gc;
  int k;
  memset(&gc, 0, sizeof gc);
  for(k = 2; k < argc; k++) {
    if(argv[k][0] == '-' && argv[k][1]) {
      fprintf(stderr, "volley ls-remote: unknown option %s\n", argv[k]);
      return 1;
    }
    if(!url) {
      url = argv[k];
    }
    else {
      if(npats >= cpats) {
        int nc = cpats ? cpats * 2 : 8;
        const char **np = realloc(pats, (size_t)nc * sizeof(const char *));
        if(!np) {
          free(pats);
          return 1;
        }
        pats = np;
        cpats = nc;
      }
      pats[npats++] = argv[k];
    }
  }
  if(!url) {
    fprintf(stderr, "usage: volley ls-remote <git-url> [ref...]\n");
    volley_help();
    return 1;
  }
  snprintf(gc.repo, sizeof gc.repo, "%s", url);
  while(gc.repo[0] && gc.repo[strlen(gc.repo) - 1] == '/')
    gc.repo[strlen(gc.repo) - 1] = 0;
  gc.refs = calloc(1 << 14, sizeof(GRef));
  if(!gc.refs) {
    free(pats);
    fprintf(stderr, "volley ls-remote: out of memory\n");
    return 1;
  }
  if(git_fetch_refs(&gc, err, sizeof err) != 0) {
    fprintf(stderr, "volley ls-remote: %s\n", err);
    free(gc.refs);
    free(pats);
    return 1;
  }
  for(k = 0; k < gc.nrefs; k++) {
    char hexh[41];
    int match = npats == 0;
    const char *nm = gc.refs[k].name;
    if(!match) {
      for(int p = 0; p < npats && !match; p++) {
        char full[360];
        if(!strcmp(nm, pats[p]) || strstr(nm, pats[p]))
          match = 1;
        snprintf(full, sizeof full, "refs/heads/%s", pats[p]);
        if(!strcmp(nm, full)) match = 1;
        snprintf(full, sizeof full, "refs/tags/%s", pats[p]);
        if(!strcmp(nm, full)) match = 1;
      }
    }
    if(!match)
      continue;
    hex16(hexh, gc.refs[k].oid);
    fprintf(stdout, "%s\t%s\n", hexh, nm);
  }
  free(gc.refs);
  free(pats);
  return 0;
}

static int cmd_git_branch(int argc, char **argv)
{
  char gitdir[4096], err[256];
  char cur[300] = "";
  GRepo r;
  RefSet set;
  int k = 2;
  if(git_repo_open(argc, argv, &k, gitdir, sizeof gitdir, err, sizeof err) != 0) {
    fprintf(stderr, "volley branch: %s\n", err);
    return 1;
  }
  if(k < argc) {
    fprintf(stderr, "volley branch: unrecognized argument %s\n", argv[k]);
    return 1;
  }
  snprintf(r.gitdir, sizeof r.gitdir, "%s", gitdir);
  memset(&set, 0, sizeof set);
  git_collect(&r, "refs/heads", "refs/heads", &set);
  {
    char path[4200];
    unsigned char *d;
    size_t n;
    snprintf(path, sizeof path, "%s/HEAD", gitdir);
    if(git_file_read(path, &d, &n) == 0) {
      if(n > 5 && !memcmp(d, "ref: ", 5)) {
        size_t s = 5, sl;
        while(s < n && d[s] && d[s] != '\n' && d[s] != '\r')
          s++;
        sl = s - 5;
        if(sl >= sizeof cur)
          sl = sizeof cur - 1;
        memcpy(cur, d + 5, sl);
        cur[sl] = 0;
      }
      free(d);
    }
  }
  refset_sort(&set);
  for(int i = 0; i < set.n; i++) {
    const char *nm = set.refs[i].name;
    const char *dn = nm + 11;
    if(!strcmp(nm, cur))
      fprintf(stdout, "* %s\n", dn);
    else
      fprintf(stdout, "  %s\n", dn);
  }
  free(set.refs);
  return 0;
}

static int cmd_git_tag(int argc, char **argv)
{
  char gitdir[4096], err[256];
  GRepo r;
  RefSet set;
  int k = 2;
  if(git_repo_open(argc, argv, &k, gitdir, sizeof gitdir, err, sizeof err) != 0) {
    fprintf(stderr, "volley tag: %s\n", err);
    return 1;
  }
  if(k < argc) {
    fprintf(stderr, "volley tag: unrecognized argument %s\n", argv[k]);
    return 1;
  }
  snprintf(r.gitdir, sizeof r.gitdir, "%s", gitdir);
  memset(&set, 0, sizeof set);
  git_collect(&r, "refs/tags", "refs/tags", &set);
  refset_sort(&set);
  for(int i = 0; i < set.n; i++)
    fprintf(stdout, "%s\n", set.refs[i].name + 10);
  free(set.refs);
  return 0;
}

static int cmd_git_remote(int argc, char **argv)
{
  char gitdir[4096], err[256], cfg[4200];
  GRepo r;
  Rmt rmts[32];
  int nrmt = 0;
  int verbose = 0;
  int k = 2;
  const char *addname = NULL, *addurl = NULL;
  if(git_repo_open(argc, argv, &k, gitdir, sizeof gitdir, err, sizeof err) != 0) {
    fprintf(stderr, "volley remote: %s\n", err);
    return 1;
  }
  snprintf(r.gitdir, sizeof r.gitdir, "%s", gitdir);
  snprintf(cfg, sizeof cfg, "%s/config", gitdir);
  for(; k < argc; k++) {
    if(!strcmp(argv[k], "-v") || !strcmp(argv[k], "--verbose")) {
      verbose = 1;
    }
    else if(!strcmp(argv[k], "add") && k + 2 < argc) {
      addname = argv[k + 1];
      addurl = argv[k + 2];
      k += 2;
    }
    else {
      fprintf(stderr, "volley remote: unrecognized argument %s\n", argv[k]);
      return 1;
    }
  }
  if(addname) {
    FILE *f;
    git_remote_list(cfg, rmts, 32, &nrmt);
    for(int i = 0; i < nrmt; i++)
      if(!strcmp(rmts[i].name, addname)) {
        fprintf(stderr, "volley remote: remote already exists: %s\n", addname);
        return 1;
      }
    f = fopen(cfg, "ab");
    if(!f) {
      fprintf(stderr, "volley remote: cannot append to %s\n", cfg);
      return 1;
    }
    fprintf(f, "\n[remote \"%s\"]\n\turl = %s\n"
               "\tfetch = +refs/heads/*:refs/remotes/%s/*\n",
            addname, addurl, addname);
    fclose(f);
    fprintf(stdout, "done. added remote %s\n", addname);
    return 0;
  }
  git_remote_list(cfg, rmts, 32, &nrmt);
  for(int i = 0; i < nrmt; i++) {
    if(verbose)
      fprintf(stdout, "%s\t%s\n", rmts[i].name, rmts[i].url);
    else
      fprintf(stdout, "%s\n", rmts[i].name);
  }
  return 0;
}

static int cmd_git_rev_parse(int argc, char **argv)
{
  char gitdir[4096], err[256];
  GRepo r;
  int k = 2;
  int bad = 0;
  if(git_repo_open(argc, argv, &k, gitdir, sizeof gitdir, err, sizeof err) != 0) {
    fprintf(stderr, "volley rev-parse: %s\n", err);
    return 1;
  }
  if(k >= argc) {
    fprintf(stderr, "usage: volley rev-parse <ref>...\n");
    return 1;
  }
  snprintf(r.gitdir, sizeof r.gitdir, "%s", gitdir);
  for(; k < argc; k++) {
    unsigned char oid[20];
    char hexh[41];
    if(git_resolve_thing(&r, argv[k], oid, err, sizeof err) != 0) {
      fprintf(stderr, "volley rev-parse: %s\n", err);
      bad = 1;
      continue;
    }
    hex16(hexh, oid);
    fprintf(stdout, "%s\n", hexh);
  }
  return bad ? 1 : 0;
}

static int cmd_git_cat_file(int argc, char **argv)
{
  char gitdir[4096], err[256];
  GRepo r;
  unsigned char oid[20];
  GObj o;
  int k = 2;
  int mode = 0;
  const char *thing = NULL;
  if(git_repo_open(argc, argv, &k, gitdir, sizeof gitdir, err, sizeof err) != 0) {
    fprintf(stderr, "volley cat-file: %s\n", err);
    return 1;
  }
  for(; k < argc; k++) {
    if(!strcmp(argv[k], "-t")) mode = 1;
    else if(!strcmp(argv[k], "-p")) mode = 2;
    else if(!strcmp(argv[k], "-s")) mode = 3;
    else if(!strcmp(argv[k], "-h")) {
      fprintf(stderr, "usage: volley cat-file -t|-p|-s <object>\n");
      return 0;
    }
    else if(!thing)
      thing = argv[k];
    else {
      fprintf(stderr, "volley cat-file: too many arguments\n");
      return 1;
    }
  }
  if(!mode || !thing) {
    fprintf(stderr, "usage: volley cat-file -t|-p|-s <object>\n");
    return 1;
  }
  snprintf(r.gitdir, sizeof r.gitdir, "%s", gitdir);
  if(git_resolve_thing(&r, thing, oid, err, sizeof err) != 0) {
    fprintf(stderr, "volley cat-file: %s\n", err);
    return 1;
  }
  if(!git_read_obj(&r, oid, &o, err, sizeof err)) {
    fprintf(stderr, "volley cat-file: %s\n", err);
    return 1;
  }
  if(mode == 1) {
    fprintf(stdout, "%s\n", git_type_name(o.type));
  }
  else if(mode == 3) {
    fprintf(stdout, "%lld\n", o.size);
  }
  else if(o.type == 2) {
    git_tree_pretty(&o, stdout);
  }
  else {
    fwrite(o.data, 1, (size_t)o.size, stdout);
  }
  free(o.data);
  return 0;
}

static int cmd_git_log(int argc, char **argv)
{
  char gitdir[4096], err[256];
  GRepo r;
  unsigned char start[20];
  const char *ref = "HEAD";
  int limit = 0;
  int hadref = 0;
  int k = 2;
  int nseen = 0;
  int printed = 0;
  unsigned char *seen;
  if(git_repo_open(argc, argv, &k, gitdir, sizeof gitdir, err, sizeof err) != 0) {
    fprintf(stderr, "volley log: %s\n", err);
    return 1;
  }
  for(; k < argc; k++) {
    if(!strcmp(argv[k], "-n") && k + 1 < argc) {
      limit = atoi(argv[k + 1]);
      k++;
    }
    else if(argv[k][0] >= '0' && argv[k][0] <= '9') {
      limit = atoi(argv[k]);
    }
    else if(argv[k][0] == '-') {
      fprintf(stderr, "volley log: unknown option %s\n", argv[k]);
      return 1;
    }
    else if(!hadref) {
      ref = argv[k];
      hadref = 1;
    }
    else {
      fprintf(stderr, "volley log: too many refs\n");
      return 1;
    }
  }
  snprintf(r.gitdir, sizeof r.gitdir, "%s", gitdir);
  if(git_resolve_thing(&r, ref, start, err, sizeof err) != 0) {
    fprintf(stderr, "volley log: %s\n", err);
    return 1;
  }
  seen = malloc(16384 * 20);
  if(!seen)
    return 1;
  memcpy(seen + (size_t)nseen * 20, start, 20);
  nseen++;
  for(int head = 0; head < nseen; head++) {
    GObj o;
    char sub[300] = "";
    const char *subp = NULL;
    int saw_blank = 0;
    if(limit > 0 && printed >= limit)
      break;
    if(nseen >= 16380) {
      fprintf(stderr, "volley log: too many commits to walk\n");
      break;
    }
    if(!git_read_obj(&r, seen + (size_t)head * 20, &o, err, sizeof err)) {
      free(seen);
      fprintf(stderr, "volley log: %s\n", err);
      return 1;
    }
    if(o.type != 1) {
      free(o.data);
      continue;
    }
    {
      const unsigned char *p = o.data;
      const unsigned char *end = o.data + o.size;
      while(p < end) {
        const unsigned char *ln = p;
        while(p < end && *p != '\n')
          p++;
        {
          size_t ll = (size_t)(p - ln);
          if(ll == 0) {
            saw_blank = 1;
          }
          else if(!saw_blank && ll >= 47 && !memcmp(ln, "parent ", 7)) {
            unsigned char po[20];
            if(git_hex40((const char *)ln + 7, po) == 0) {
              int dup = 0;
              for(int s = 0; s < nseen; s++)
                if(!memcmp(seen + (size_t)s * 20, po, 20)) {
                  dup = 1;
                  break;
                }
              if(!dup) {
                memcpy(seen + (size_t)nseen * 20, po, 20);
                nseen++;
              }
            }
          }
          else if(saw_blank && !subp) {
            const char *st = (const char *)ln;
            size_t sn;
            while(st < (const char *)end && (*st == ' ' || *st == '\t'))
              st++;
            sn = (size_t)((const char *)p - st);
            while(sn && (st[sn - 1] == ' ' || st[sn - 1] == '\t' ||
                         st[sn - 1] == '\r'))
              sn--;
            if(sn >= sizeof sub)
              sn = sizeof sub - 1;
            memcpy(sub, st, sn);
            sub[sn] = 0;
            subp = sub;
          }
        }
        if(p < end)
          p++;
      }
    }
    {
      char hexh[41];
      hex16(hexh, o.oid);
      fprintf(stdout, "%.7s %s\n", hexh, subp ? subp : "(no subject)");
    }
    printed++;
    free(o.data);
  }
  free(seen);
  return 0;
}

static int cmd_git_ls_tree(int argc, char **argv)
{
  char gitdir[4096], err[256];
  GRepo r;
  unsigned char oid[20], treeoid[20];
  GObj t;
  GObj *to;
  int k = 2;
  const char *thing = "HEAD";
  if(git_repo_open(argc, argv, &k, gitdir, sizeof gitdir, err, sizeof err) != 0) {
    fprintf(stderr, "volley ls-tree: %s\n", err);
    return 1;
  }
  if(k < argc) {
    thing = argv[k];
    k++;
  }
  if(k < argc) {
    fprintf(stderr, "volley ls-tree: too many arguments\n");
    return 1;
  }
  snprintf(r.gitdir, sizeof r.gitdir, "%s", gitdir);
  if(git_resolve_thing(&r, thing, oid, err, sizeof err) != 0) {
    fprintf(stderr, "volley ls-tree: %s\n", err);
    return 1;
  }
  to = git_treeish(&r, oid, treeoid, &t, err, sizeof err) == 0 ? &t : NULL;
  if(!to) {
    fprintf(stderr, "volley ls-tree: %s\n", err);
    return 1;
  }
  git_tree_pretty(to, stdout);
  free(to->data);
  return 0;
}

static int cmd_git_init(int argc, char **argv)
{
  const char *dest = ".";
  int bare = 0;
  int quiet = 0;
  int k;
  char gitdir[4200], sub[4200], buf[4096], err[512];
  if(argc < 2)
    return 1;
  for(k = 2; k < argc; k++) {
    if(!strcmp(argv[k], "-q") || !strcmp(argv[k], "--quiet"))
      quiet = 1;
    else if(!strcmp(argv[k], "--bare"))
      bare = 1;
    else if(argv[k][0] == '-' && argv[k][1]) {
      fprintf(stderr, "volley init: unknown option %s\n", argv[k]);
      return 1;
    }
    else {
      dest = argv[k];
      if(k + 1 < argc) {
        fprintf(stderr, "volley init: too many arguments\n");
        return 1;
      }
    }
  }
  {
    size_t n = strlen(dest);
    while(n && dest[n - 1] == '/')
      n--;
    if(bare) {
      if(n == 0)
        snprintf(gitdir, sizeof gitdir, ".");
      else {
        if(n >= sizeof gitdir) {
          fprintf(stderr, "volley init: path too long\n");
          return 1;
        }
        memcpy(gitdir, dest, n);
        gitdir[n] = 0;
      }
    }
    else if(n == 0)
      snprintf(gitdir, sizeof gitdir, ".git");
    else if(n + 6 <= sizeof gitdir) {
      memcpy(gitdir, dest, n);
      memcpy(gitdir + n, "/.git", 6);
    }
    else {
      fprintf(stderr, "volley init: path too long\n");
      return 1;
    }
  }
  if(git_mkdir_p(gitdir) != 0) {
    fprintf(stderr, "volley init: cannot create %s\n", gitdir);
    return 1;
  }
  snprintf(sub, sizeof sub, "%s/objects/info", gitdir);
  git_mkdir_p(sub);
  snprintf(sub, sizeof sub, "%s/objects/pack", gitdir);
  git_mkdir_p(sub);
  snprintf(sub, sizeof sub, "%s/refs/heads", gitdir);
  git_mkdir_p(sub);
  snprintf(sub, sizeof sub, "%s/refs/tags", gitdir);
  git_mkdir_p(sub);
  snprintf(buf, sizeof buf, "ref: refs/heads/master\n");
  {
    char path[4200];
    snprintf(path, sizeof path, "%s/HEAD", gitdir);
    if(git_write_all(path, (const unsigned char *)buf, strlen(buf), err, sizeof err) != 0) {
      fprintf(stderr, "volley init: %s\n", err);
      return 1;
    }
  }
  snprintf(buf, sizeof buf,
           "[core]\n"
           "\trepositoryformatversion = 0\n"
           "\tfilemode = true\n"
           "\tbare = %s\n"
           "\tlogallrefupdates = true\n",
           bare ? "true" : "false");
  {
    char path[4200];
    snprintf(path, sizeof path, "%s/config", gitdir);
    if(git_write_all(path, (const unsigned char *)buf, strlen(buf), err, sizeof err) != 0) {
      fprintf(stderr, "volley init: %s\n", err);
      return 1;
    }
  }
  if(!quiet)
    fprintf(stdout, "done. initialized empty repository at %s\n", gitdir);
  return 0;
}
#endif /* !VOLLEY_LIB */

/* ---------------------------------------------------------------- */
/* public API (libvolley)                                            */
/* ---------------------------------------------------------------- */
void volley_global_init(void)
{
  engine_start();
}

void volley_global_cleanup(void)
{
  engine_cleanup();
}

const char *volley_version(void)
{
  return VOLLEY_VERSION_STRING;
}

int volley_parse_url(const char *url, struct volley_url *out)
{
  Url u;
  if(parse_url(url, &u) != 0)
    return -1;
  memset(out, 0, sizeof *out);
  snprintf(out->scheme, sizeof out->scheme, "%s", u.scheme);
  snprintf(out->host, sizeof out->host, "%s", u.host);
  snprintf(out->port, sizeof out->port, "%s", u.port);
  snprintf(out->path, sizeof out->path, "%s", u.path);
  snprintf(out->auth, sizeof out->auth, "%s", u.auth);
  out->https = u.https;
  return 0;
}

void volley_url_free(struct volley_url *u)
{
  (void)u;
}

int volley_fetch(const struct volley_opts *o, struct volley_result *r)
{
  Cfg cfg;
  Jb jb;
  XOpt xo;
  Res res;
  const char *extra[16];
  int nex = 0;

  if(!r)
    return -1;
  memset(r, 0, sizeof *r);
  r->bytes = -1;
  r->total = -1;
  if(engine_start() != 0) {
    snprintf(r->err, sizeof r->err, "engine failed to start");
    return -1;
  }
  memset(&cfg, 0, sizeof cfg);
  snprintf(cfg.method, sizeof cfg.method, "%s",
           o && o->method ? o->method : "GET");
  cfg.nurls = 1;
  cfg.parallel = 1;
  cfg.segs = 1;
  cfg.insecure = o ? o->insecure : 0;
  cfg.follow = o ? o->follow : 1;
  cfg.silent = 1;
  cfg.body = (char *)(o ? o->body : NULL);
  cfg.body_len = o ? o->body_len : 0;
  cfg.range = o ? o->range : NULL;
  cfg.useragent = o ? o->useragent : NULL;
  if(o && o->headers) {
    for(int i = 0; o->headers[i] && nex < 16; i++)
      extra[nex++] = o->headers[i];
  }
  cfg.uhdrs = (char **)extra;
  cfg.nuhdrs = nex;
  memset(&jb, 0, sizeof jb);
  jb.url = o->url;
  if(parse_url(jb.url, &jb.u) != 0) {
    snprintf(r->err, sizeof r->err, "malformed url");
    return -1;
  }
  memset(&xo, 0, sizeof xo);
  xo.no_decode = o ? o->no_content_decode : 0;
  do_transfer(&cfg, &jb, &res, &xo);
  if(res.err[0])
    strncpy(g_lasterr, res.err, sizeof g_lasterr - 1);
  else
    g_lasterr[0] = 0;
  r->status = res.status;
  r->ok = res.net_ok;
  r->bytes = res.bytes;
  r->total = res.total;
  r->ms = res.ms;
  snprintf(r->err, sizeof r->err, "%s", res.err);
  snprintf(r->final_url, sizeof r->final_url, "%s",
           res.final_url[0] ? res.final_url : "");
  if(res.body.data) {
    r->body = (unsigned char *)res.body.data;
    r->body_len = res.body.len;
    res.body.data = NULL;
  }
  return res.net_ok ? 0 : -1;
}

void volley_result_free(struct volley_result *r)
{
  if(r) {
    free(r->body);
    r->body = NULL;
    r->body_len = 0;
  }
}

int volley_get(const char *url, struct volley_result *r,
               char *err, size_t errsz)
{
  struct volley_opts o;
  memset(&o, 0, sizeof o);
  o.url = url;
  if(volley_fetch(&o, r) != 0 && err)
    snprintf(err, errsz, "%s", r->err);
  return r->status;
}

int volley_head(const char *url, struct volley_result *r,
                char *err, size_t errsz)
{
  struct volley_opts o;
  memset(&o, 0, sizeof o);
  o.url = url;
  o.method = "HEAD";
  if(volley_fetch(&o, r) != 0 && err)
    snprintf(err, errsz, "%s", r->err);
  return r->status;
}

int volley_b64_encode(const unsigned char *in, size_t inlen,
                      char *out, size_t outcap)
{
  size_t need = ((inlen + 2) / 3) * 4 + 1;
  if(need > outcap)
    return -1;
  base64_encode(in, inlen, out);
  return 0;
}

int volley_b64_decode(const char *in, unsigned char *out,
                      size_t outcap, size_t *outlen)
{
  size_t oi = 0;
  int j = 0;
  unsigned char ibuf[4];
  const char *p = in;
  int pad = 0;
  while(*p) {
    int v = -1;
    char c = *p++;
    if(c == '=') {
      pad = 1;
      continue;
    }
    if(isspace((unsigned char)c))
      continue;
    if(c >= 'A' && c <= 'Z') v = c - 'A';
    else if(c >= 'a' && c <= 'z') v = c - 'a' + 26;
    else if(c >= '0' && c <= '9') v = c - '0' + 52;
    else if(c == '+') v = 62;
    else if(c == '/') v = 63;
    if(v < 0)
      return -2;
    if(pad)
      return -2;
    ibuf[j++] = (unsigned char)v;
    if(j == 4) {
      if(oi + 3 > outcap)
        return -1;
      out[oi++] = (unsigned char)((ibuf[0] << 2) | (ibuf[1] >> 4));
      out[oi++] = (unsigned char)((ibuf[1] << 4) | (ibuf[2] >> 2));
      out[oi++] = (unsigned char)((ibuf[2] << 6) | ibuf[3]);
      j = 0;
    }
  }
  if(j > 0) {
    while(j < 4)
      ibuf[j++] = 0;
    if(oi + 2 > outcap)
      return -1;
    out[oi++] = (unsigned char)((ibuf[0] << 2) | (ibuf[1] >> 4));
    if(j >= 2)
      out[oi++] = (unsigned char)((ibuf[1] << 4) | (ibuf[2] >> 2));
  }
  *outlen = oi;
  return 0;
}

int volley_gzip_inflate(const unsigned char *in, size_t inlen,
                        unsigned char **out, size_t *outlen,
                        char *err, size_t errsz)
{
  Buffer b;
  memset(&b, 0, sizeof b);
  if(git_inflate_all(in, inlen, &b) != 0) {
    free(b.data);
    if(err)
      snprintf(err, errsz, "not a gzip/zlib stream");
    return -1;
  }
  *out = (unsigned char *)b.data;
  *outlen = b.len;
  return 0;
}

int volley_git_clone(const char *url, const char *destdir,
                     const struct volley_git_opts *o,
                     char *err, size_t errsz)
{
  if(engine_start() != 0) {
    snprintf(err, errsz, "engine failed to start");
    return -1;
  }
  if(!url || !url[0] || !destdir || !destdir[0]) {
    if(err)
      snprintf(err, errsz, "url and destdir are required");
    return -1;
  }
  return git_clone_impl(url, destdir, o, err, errsz);
}

/* ---------------------------------------------------------------- */
/* last error + large downloads                                      */
/* ---------------------------------------------------------------- */

/* Thread-local error from the most recent volley_* call that failed in the
 * calling thread; NULL when the last call succeeded (or never happened).
 * Note: transfer helpers (volley_fetch / volley_head / volley_large_fetch)
 * record into this; pure helper failures (e.g. volley_b64_*) do not. */
const char *volley_last_error(void)
{
  return g_lasterr[0] ? g_lasterr : NULL;
}

void volley_error_clear(void)
{
  g_lasterr[0] = 0;
}

/* Stream a (possibly very large) resource straight to `path` with O(1)
 * memory: the engine writes the body to disk as it arrives instead of
 * buffering it in RAM. Behaviour mirrors classic download modes:
 *
 *   - "Accept-Encoding: identity" is sent so the file holds exactly the
 *     bytes on the wire (no transparent gzip decode, range-resume intact);
 *   - resume_at > 0 issues "Range: bytes=<resume_at>-" and appends;
 *   - a 206 response is validated against the requested resume point and
 *     member of its Content-Range ("bytes first-last/total"); on mismatch
 *     the partial file is restored to its pre-call size and -1 returned;
 *   - if the server ignores the Range (200), the download restarts from
 *     byte 0 (truncating the file first), like httpie -c.
 *
 * Returns 0 on transport-level success (check r->status for the HTTP code);
 * -1 on transport errors or an invalid Content-Range (r->err + 
 * volley_last_error() describe the problem). r->body is never filled. */
int volley_large_fetch(const char *url, const char *path, long long resume_at,
                       struct volley_result *r)
{
  Cfg cfg;
  Jb jb;
  XOpt xo;
  Res res;
  FILE *fp = NULL;
  long long at = resume_at;
  char rng[64];
  char encl_hdr[32];
  char *uhdrs[1] = {NULL};
  int attempt;

  if(!r)
    return -1;
  memset(r, 0, sizeof *r);
  r->bytes = -1;
  r->total = -1;
  if(!url || !url[0] || !path || !path[0]) {
    snprintf(g_lasterr, sizeof g_lasterr, "url and path are required");
    snprintf(r->err, sizeof r->err, "%s", g_lasterr);
    return -1;
  }
  if(engine_start() != 0) {
    if(!g_lasterr[0])
      snprintf(g_lasterr, sizeof g_lasterr, "engine failed to start");
    snprintf(r->err, sizeof r->err, "%s", g_lasterr);
    return -1;
  }

  memset(&jb, 0, sizeof jb);
  jb.url = url;
  snprintf(jb.save_path, sizeof jb.save_path, "%s", path);
  if(parse_url(url, &jb.u) != 0) {
    snprintf(g_lasterr, sizeof g_lasterr, "malformed url: %s", url);
    snprintf(r->err, sizeof r->err, "%s", g_lasterr);
    return -1;
  }

  snprintf(encl_hdr, sizeof encl_hdr, "Accept-Encoding: identity");
  uhdrs[0] = encl_hdr;

  for(attempt = 0; attempt < 2; attempt++) {
    memset(&cfg, 0, sizeof cfg);
    snprintf(cfg.method, sizeof cfg.method, "GET");
    cfg.nurls = 1;
    cfg.parallel = 1;
    cfg.segs = 1;
    cfg.follow = 1;
    cfg.silent = 1;
    cfg.uhdrs = uhdrs;
    cfg.nuhdrs = 1;
    memset(&xo, 0, sizeof xo);
    xo.no_decode = 1;     /* store raw bytes exactly as sent */
    if(at > 0) {
      snprintf(rng, sizeof rng, "%lld-", at);
      xo.range = rng;
      fp = fopen(path, "ab");
    }
    else {
      fp = fopen(path, "wb");
    }
    if(!fp) {
      snprintf(g_lasterr, sizeof g_lasterr, "can't open %s: %s", path,
               strerror(errno));
      snprintf(r->err, sizeof r->err, "%s", g_lasterr);
      return -1;
    }
    xo.stream_to = fp;
    memset(&res, 0, sizeof res);
    res.bytes = -1;
    res.total = -1;
    do_transfer(&cfg, &jb, &res, &xo);
    fclose(fp);
    fp = NULL;

    if(at > 0 && res.net_ok && res.status == 206) {
      /* Content-Range must agree with what we asked for. */
      if(!res.cr_ok || res.cr_first != at ||
         (res.total >= 0 && res.cr_last + 1 != res.total)) {
        char er[256];
        snprintf(er, sizeof er,
                 "unexpected Content-Range for requested Range \"bytes=%lld-\"",
                 at);
        if(res.cr_ok)
          snprintf(er + (int)strlen(er), (size_t)(sizeof er - strlen(er)),
                   " (%lld-%lld/%lld)", res.cr_first, res.cr_last, res.total);
        truncate(path, at);   /* restore the partial file */
        snprintf(g_lasterr, sizeof g_lasterr, "%s", er);
        snprintf(r->err, sizeof r->err, "%s", er);
        return -1;
      }
      break;
    }

    /* Server ignored the Range (200): restart from byte 0 like httpie. */
    if(at > 0 && res.net_ok && res.status >= 200 && res.status < 300) {
      at = 0;
      continue;
    }

    /* HTTP error on a resume attempt: don't leave error-page bytes appended. */
    if(at > 0 && res.net_ok && res.status >= 400)
      truncate(path, at);
    break;
  }

  r->status = res.status;
  r->ok = res.net_ok;
  r->bytes = res.bytes;
  r->total = res.total;
  r->ms = res.ms;
  snprintf(r->err, sizeof r->err, "%s", res.err);
  snprintf(r->final_url, sizeof r->final_url, "%s",
           res.final_url[0] ? res.final_url : "");
  if(res.err[0])
    strncpy(g_lasterr, res.err, sizeof g_lasterr - 1);
  else
    g_lasterr[0] = 0;
  return res.net_ok ? 0 : -1;
}

#ifndef VOLLEY_LIB

/* ---------------------------------------------------------------- */
/* httpie-style persistent sessions (JSON, per-host)                */
/* ---------------------------------------------------------------- */

/* write a JSON string, escaping " and \ and control chars */
static void sess_json_str(const char *s, FILE *f)
{
  fputc('"', f);
  for(const unsigned char *p = (const unsigned char *)s; *p; p++) {
    if(*p == '"' || *p == '\\')
      fprintf(f, "\\%c", *p);
    else if(*p == '\n')
      fwrite("\\n", 1, 2, f);
    else if(*p == '\r')
      fwrite("\\r", 1, 2, f);
    else if(*p == '\t')
      fwrite("\\t", 1, 2, f);
    else if(*p < 0x20)
      fprintf(f, "\\u%04x", *p);
    else
      fputc(*p, f);
  }
  fputc('"', f);
}

/* pull the value of "key" out of a JSON object; string or bare token.
   Returns 0 on success and stores the (unescaped) value in out. */
static int sess_json_get(const char *obj, const char *key,
                         char *out, size_t n)
{
  char pat[64];
  const char *p;
  snprintf(pat, sizeof pat, "\"%s\"", key);
  p = strstr(obj, pat);
  if(!p)
    return -1;
  p += strlen(pat);
  while(*p && *p != ':') p++;
  if(!*p) return -1;
  p++;
  while(*p && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
  if(*p == '"') {
    size_t k = 0;
    p++;
    while(*p && *p != '"' && k + 1 < n) {
      if(*p == '\\' && p[1]) {
        if(p[1] == 'u' && p[2] && p[3] && p[4] && p[5]) {
          int hi = 0;
          for(int z = 0; z < 4; z++) {
            char c = p[2 + z];
            hi = (hi << 4) |
                 (c >= '0' && c <= '9' ? c - '0' :
                  (c >= 'a' && c <= 'f' ? c - 'a' + 10 :
                   (c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1)));
            if(hi < 0) break;
          }
          if(hi >= 0) {
            out[k++] = (char)hi;
            p += 6;
            continue;
          }
        }
        p++;
        if(*p == 'n') out[k++] = '\n';
        else if(*p == 'r') out[k++] = '\r';
        else if(*p == 't') out[k++] = '\t';
        else out[k++] = *p;
      }
      else
        out[k++] = *p;
      if(k + 1 < n) p++;
    }
    out[k] = 0;
    return 0;
  }
  /* bare token or number */
  {
    size_t k = 0;
    while(*p && *p != ',' && *p != '}' && *p != ' ' && *p != '\t' &&
          *p != '\n' && *p != '\r' && k + 1 < n)
      out[k++] = *p++;
    out[k] = 0;
    return 0;
  }
}

/* skip a JSON value token (started just after ':'): returns position
   after the value. Handles strings, bare tokens, objects, arrays. */
static const char *sess_json_skip(const char *p)
{
  while(*p && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
  if(*p == '"') {
    p++;
    while(*p) {
      if(*p == '\\' && p[1]) { p += 2; continue; }
      if(*p == '"') return p + 1;
      p++;
    }
    return p;
  }
  if(*p == '{' || *p == '[') {
    char open = *p;
    int depth = 0;
    for(; *p; p++) {
      if(*p == '"') {
        p++;
        while(*p) {
          if(*p == '\\' && p[1]) { p += 2; continue; }
          if(*p == '"') break;
          p++;
        }
      }
      else if(*p == open) depth++;
      else if(*p == (open == '{' ? '}' : ']')) {
        depth--;
        if(depth == 0) return p + 1;
      }
    }
    return p;
  }
  while(*p && *p != ',' && *p != '}' && *p != ']' &&
        *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r')
    p++;
  return p;
}

static void sess_hdr_add(const char *hv)
{
  char name[256];
  const char *colon = strchr(hv, ':');
  size_t nl = colon ? (size_t)(colon - hv) : strlen(hv);
  size_t k = nl < sizeof name - 1 ? nl : sizeof name - 1;
  memcpy(name, hv, k); name[k] = 0;
  for(int i = 0; i < g_nsessh; i++) {
    const char *colon2 = g_sess_hdrs[i] ? strchr(g_sess_hdrs[i], ':') : NULL;
    size_t nl2 = colon2 ? (size_t)(colon2 - g_sess_hdrs[i])
                        : (g_sess_hdrs[i] ? strlen(g_sess_hdrs[i]) : 0);
    if(g_sess_hdrs[i] && nl2 == k &&
       !strncasecmp(g_sess_hdrs[i], name, k)) {
      if(hv != g_sess_hdrs[i]) {
        free(g_sess_hdrs[i]);
        g_sess_hdrs[i] = strdup(hv);
      }
      return;               /* replaced: caller value wins */
    }
  }
  if(g_nsessh < 64)
    g_sess_hdrs[g_nsessh++] = strdup(hv);
}

/* does any pre-existing header already carry this name? */
static int sess_hdr_exists(char **hdrs, int n, const char *hv)
{
  const char *colon = strchr(hv, ':');
  size_t nl = colon ? (size_t)(colon - hv) : strlen(hv);
  for(int i = 0; i < n; i++) {
    const char *c = strchr(hdrs[i], ':');
    size_t nl2 = c ? (size_t)(c - hdrs[i]) : strlen(hdrs[i]);
    if(nl2 == nl && !strncasecmp(hdrs[i], hv, nl))
      return 1;
  }
  return 0;
}

/* headers that must never persist into a session */
static int sess_hdr_transient(const char *hv)
{
  char name[256];
  const char *colon = strchr(hv, ':');
  size_t nl = colon ? (size_t)(colon - hv) : strlen(hv);
  size_t k = nl < sizeof name - 1 ? nl : sizeof name - 1;
  memcpy(name, hv, k); name[k] = 0;
  if(!strncasecmp(name, "Content-", 8) || !strncasecmp(name, "If-", 3))
    return 1;
  if(!strcasecmp(name, "Host") || !strcasecmp(name, "Content-Length") ||
     !strcasecmp(name, "Connection") || !strcasecmp(name, "Transfer-Encoding") ||
     !strcasecmp(name, "Expect") || !strcasecmp(name, "Accept-Encoding") ||
     !strcasecmp(name, "Range"))
    return 1;
  return 0;
}

static const char *sess_config_dir(void)
{
  static char dir[2048];
  const char *xdg = getenv("XDG_CONFIG_HOME");
  const char *home = getenv("HOME");
  if(xdg && xdg[0])
    snprintf(dir, sizeof dir, "%s/volley/sessions", xdg);
  else if(home && home[0])
    snprintf(dir, sizeof dir, "%s/.config/volley/sessions", home);
  else
    snprintf(dir, sizeof dir, "/tmp/volley-sessions");
  return dir;
}

static void sess_resolve(const char *name, const char *host, const char *port)
{
  char hp[600];
  if(strchr(name, '/') || strchr(name, '\\')) {
    /* anonymous session: literal path (httpie expanduser) */
    if(name[0] == '~' && (name[1] == '/' || name[1] == 0)) {
      const char *home = getenv("HOME");
      snprintf(g_sess_path, sizeof g_sess_path, "%s%s",
               home ? home : "", name + 1);
    }
    else
      snprintf(g_sess_path, sizeof g_sess_path, "%s", name);
  }
  else {
    const char *dir = sess_config_dir();
    snprintf(hp, sizeof hp, "%s", host);
    if(port[0] && strcmp(port, "80") && strcmp(port, "443"))
      snprintf(hp + strlen(hp), sizeof hp - strlen(hp), ":%s", port);
    snprintf(g_sess_path, sizeof g_sess_path, "%s/%s/%s.json", dir, hp, name);
  }
  g_sess_active = 1;
  snprintf(g_sess_host, sizeof g_sess_host, "%s", host);
}

static void sess_load(void)
{
  FILE *f = fopen(g_sess_path, "r");
  char *buf = NULL;
  long sz;
  if(!f)
    return;
  if(fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0 ||
     sz > (long)(8 << 20)) {
    fclose(f);
    return;
  }
  fseek(f, 0, SEEK_SET);
  buf = malloc((size_t)sz + 1);
  if(buf) {
    size_t got = fread(buf, 1, (size_t)sz, f);
    buf[got] = 0;
  }
  fclose(f);
  if(!buf)
    return;

  /* headers: [ {"name":..., "value":...}, ... ] */
  {
    const char *h = strstr(buf, "\"headers\"");
    if(h) {
      h = strchr(h, ':');
      h = h ? h + 1 : buf;
      while(*h && *h != '[') h++;
      if(*h == '[') {
        const char *p = h + 1;
        while(*p && *p != ']') {
          char nm[512], vl[4096], hv[4608];
          while(*p && *p != '{' && *p != ']') p++;
          if(*p != '{') break;
          if(sess_json_get(p, "name", nm, sizeof nm) == 0 &&
             sess_json_get(p, "value", vl, sizeof vl) == 0) {
            snprintf(hv, sizeof hv, "%s: %s", nm, vl);
            sess_hdr_add(hv);
          }
          p = sess_json_skip(p);   /* p is at '{': skip the whole object */
        }
      }
    }
  }

  /* cookies: [ {...}, ... ] -> jar */
  {
    const char *c = strstr(buf, "\"cookies\"");
    if(c) {
      c = strchr(c, ':');
      c = c ? c + 1 : buf;
      while(*c && *c != '[') c++;
      if(*c == '[') {
        const char *p = c + 1;
        while(*p && *p != ']') {
          char nm[256], vl[1024], dom[256], cp[512], sec[16], ex[32];
          while(*p && *p != '{' && *p != ']') p++;
          if(*p != '{') break;
          dom[0] = cp[0] = sec[0] = ex[0] = 0;
          if(sess_json_get(p, "name", nm, sizeof nm) != 0 ||
             sess_json_get(p, "value", vl, sizeof vl) != 0)
            break;
          sess_json_get(p, "domain", dom, sizeof dom);
          sess_json_get(p, "path", cp, sizeof cp);
          sess_json_get(p, "secure", sec, sizeof sec);
          sess_json_get(p, "expires", ex, sizeof ex);
          cook_add(dom[0] ? dom : g_sess_host, cp[0] ? cp : "/", nm, vl,
                   (long long)strtoll(ex, NULL, 10),
                   (!strcasecmp(sec, "true") || !strcmp(sec, "1")) ? 1 : 0);
          p = sess_json_skip(p);   /* p is at '{': skip the whole object */
        }
      }
    }
  }
  free(buf);
}

static void sess_save(void)
{
  FILE *f;
  char tmp[2200];
  const char *slash = g_sess_path[0] ? strrchr(g_sess_path, '/') : NULL;
  char dir[2048];
  long long now = cookie_now();
  size_t dn;
  if(!g_sess_active || !g_sess_path[0])
    return;
  dn = slash ? (size_t)(slash - g_sess_path) : 0;
  if(dn >= sizeof dir) dn = sizeof dir - 1;
  memcpy(dir, g_sess_path, dn); dir[dn] = 0;
  if(dn) {
    char cmd[2400];
    snprintf(cmd, sizeof cmd, "mkdir -p -- '%s'", dir);
    (void)!system(cmd);
  }
  cookie_purge();
  snprintf(tmp, sizeof tmp, "%s.XXXXXX", g_sess_path);
  f = NULL;
  {
    int fd = mkstemp(tmp);
    if(fd < 0) {
      f = fopen(g_sess_path, "w");
      tmp[0] = 0;
    }
    else
      f = fdopen(fd, "w");
  }
  if(!f)
    return;
  fputs("{\n  \"headers\": [", f);
  {
    int first = 1;
    for(int i = 0; i < g_nsessh; i++) {
      if(!g_sess_hdrs[i] || sess_hdr_transient(g_sess_hdrs[i]))
        continue;
      if(!first) fputs(",", f);
      first = 0;
      fputs("\n    { \"name\": ", f);
      {
        char nm[300];
        const char *colon = strchr(g_sess_hdrs[i], ':');
        size_t nl = colon ? (size_t)(colon - g_sess_hdrs[i])
                          : strlen(g_sess_hdrs[i]);
        size_t k = nl < sizeof nm - 1 ? nl : sizeof nm - 1;
        memcpy(nm, g_sess_hdrs[i], k); nm[k] = 0;
        sess_json_str(nm, f);
      }
      fputs(", \"value\": ", f);
      {
        const char *colon = strchr(g_sess_hdrs[i], ':');
        const char *val = colon ? colon + 1 : "";
        while(*val == ' ') val++;
        sess_json_str(val, f);
      }
      fputs(" }", f);
    }
    fputs("\n  ],\n  \"cookies\": [", f);
    first = 1;
    for(int i = 0; i < g_ncookies; i++) {
      Cookie *ck = &g_jar[i];
      if(!ck->alive)
        continue;
      if(ck->expiry && ck->expiry < now)
        continue;
      if(!cookie_domain_match(ck->domain, g_sess_host))
        continue;
      if(!first) fputs(",", f);
      first = 0;
      fprintf(f, "\n    { \"name\": ");
      sess_json_str(ck->name, f);
      fprintf(f, ", \"value\": ");
      sess_json_str(ck->value, f);
      if(ck->expiry) {
        fprintf(f, ", \"expires\": %lld", ck->expiry);
      }
      else
        fputs(", \"expires\": 0", f);
      fprintf(f, ", \"path\": ");
      sess_json_str(ck->path, f);
      fprintf(f, ", \"domain\": ");
      sess_json_str(ck->domain, f);
      fputs(ck->secure ? ", \"secure\": true }" : ", \"secure\": false }", f);
    }
  }
  fputs("\n  ],\n  \"auth\": { \"type\": null }\n}\n", f);
  fflush(f);
  if(tmp[0]) {
    fclose(f);
    rename(tmp, g_sess_path);
  }
  else
    fclose(f);
}

/* ---------------------------------------------------------------- */
/* main                                                              */
/* ---------------------------------------------------------------- */
int main(int argc, char **argv)
{
  {
    /* git-style invocation: "volley -C <dir> <subcmd> ..." means the repo
       option comes before the subcommand. Reorder so argv[1] is always the
       subcommand name; each handler re-parses its own -C/--git-dir. */
    if(argc >= 4 && (!strcmp(argv[1], "-C") || !strcmp(argv[1], "--git-dir")) &&
       git_argv_is_cmd(argv[3])) {
      static char *na[64];
      int n = 0;
      int i;
      na[n++] = argv[0];
      na[n++] = argv[3];
      na[n++] = argv[1];
      na[n++] = argv[2];
      for(i = 4; i < argc && n + 1 < (int)(sizeof na / sizeof na[0]); i++)
        na[n++] = argv[i];
      argv = na;
      argc = n;
    }
  }
  if(argc >= 2 && !strcmp(argv[1], "clone")) {
    struct volley_git_opts go;
    const char *url = NULL, *dir = NULL;
    char err[1024];
    char defdir[4096];
    int r;
    memset(&go, 0, sizeof go);
    for(int k = 2; k < argc; k++) {
      if(!strcmp(argv[k], "-q") || !strcmp(argv[k], "--quiet"))
        go.quiet = 1;
      else if(!strcmp(argv[k], "-v") || !strcmp(argv[k], "--verbose"))
        go.verbose = 1;
      else if(!strcmp(argv[k], "--bare"))
        go.bare = 1;
      else if(!url)
        url = argv[k];
      else if(!dir)
        dir = argv[k];
      else {
        fprintf(stderr, "volley clone: too many arguments\n");
        return 1;
      }
    }
    if(!url) {
      volley_help();
      return 1;
    }
    if(!dir) {
      git_default_dir(url, defdir, sizeof defdir);
      dir = defdir;
    }
    r = volley_git_clone(url, dir, &go, err, sizeof err);
    if(r != 0) {
      fprintf(stderr, "volley clone: %s\n", err[0] ? err : "clone failed");
      return 1;
    }
    return 0;
  }

  if(argc >= 2 && !strcmp(argv[1], "ls-remote"))
    return cmd_git_ls_remote(argc, argv);
  if(argc >= 2 && !strcmp(argv[1], "branch"))
    return cmd_git_branch(argc, argv);
  if(argc >= 2 && !strcmp(argv[1], "tag"))
    return cmd_git_tag(argc, argv);
  if(argc >= 2 && !strcmp(argv[1], "remote"))
    return cmd_git_remote(argc, argv);
  if(argc >= 2 && !strcmp(argv[1], "rev-parse"))
    return cmd_git_rev_parse(argc, argv);
  if(argc >= 2 && !strcmp(argv[1], "cat-file"))
    return cmd_git_cat_file(argc, argv);
  if(argc >= 2 && !strcmp(argv[1], "log"))
    return cmd_git_log(argc, argv);
  if(argc >= 2 && !strcmp(argv[1], "ls-tree"))
    return cmd_git_ls_tree(argc, argv);
  if(argc >= 2 && !strcmp(argv[1], "init"))
    return cmd_git_init(argc, argv);

  /* configuration file: explicit -K wins, else ~/.volleyrc or ~/.wgetrc */
  {
    const char *confarg = NULL;
    for(int k = 1; k < argc - 1; k++) {
      if((!strcmp(argv[k], "-K") || !strcmp(argv[k], "--config")) &&
         argv[k+1])
        confarg = argv[k+1];
    }
    config_load(confarg);
  }

  static struct option lopt[] = {
    {"request",    required_argument, 0, 'X'},
    {"header",     required_argument, 0, 'H'},
    {"data",       required_argument, 0, 'd'},
    {"form",       required_argument, 0, 'F'},
    {"output",     required_argument, 0, 'o'},
    {"remote-name",no_argument,       0, 'O'},
    {"head",       no_argument,       0, 'I'},
    {"parallel",   required_argument, 0, 'j'},
    {"segments",   required_argument, 0, 'c'},
    {"insecure",   no_argument,       0, 'k'},
    {"location",   no_argument,       0, 'L'},
    {"no-location",no_argument,       0, 1000},
    {"verbose",    no_argument,       0, 'v'},
    {"silent",     no_argument,       0, 's'},
    {"include",    no_argument,       0, 'i'},
    {"max-time",   required_argument, 0, 'm'},
    {"fail",       no_argument,       0, 'f'},
    {"range",      required_argument, 0, 'r'},
    {"user",       required_argument, 0, 'u'},
    {"user-agent", required_argument, 0, 'A'},
    {"proxy",      required_argument, 0, 'x'},
    {"proxy-user", required_argument, 0, 'U'},
    {"continue-at",required_argument, 0, 'C'},
    {"ipv4",       no_argument,       0, '4'},
    {"ipv6",       no_argument,       0, '6'},
    {"upload-file",required_argument, 0, 'T'},
    {"session",    required_argument, 0, 'S'},
    {"cookie",     required_argument, 0, 'b'},
    {"list-only",  no_argument,       0, 'l'},
    {"config",     required_argument, 0, 'K'},
    {"color",      required_argument, 0, 1001},
    {"no-encoding",no_argument,       0, 1002},
    {"cookie-jar", required_argument, 0, 1003},
    {"junk-session-cookies", no_argument, 0, 1004},
    {"progress",   required_argument, 0, 1005},
    {"limit-rate", required_argument, 0, 1006},
    {"connect-timeout", required_argument, 0, 1007},
    {"retry",      required_argument, 0, 1008},
    {"retry-all-errors", no_argument, 0, 1009},
    {"retry-delay",required_argument, 0, 1010},
    {"netrc",      no_argument,       0, 1011},
    {"no-netrc",   no_argument,       0, 1012},
    {"netrc-file", required_argument, 0, 1013},
    {"http2",      no_argument,       0, 1014},
    {"http1.1",    no_argument,       0, 1015},
    {"http11",     no_argument,       0, 1015},
    {"recursive",  no_argument,       0, 1016},
    {"mirror",     no_argument,       0, 1017},
    {"level",      required_argument, 0, 1018},
    {"domains",    required_argument, 0, 1019},
    {"span-hosts", no_argument,       0, 1020},
    {"accept",     required_argument, 0, 1021},
    {"reject",     required_argument, 0, 1022},
    {"directory-prefix", required_argument, 0, 1023},
    {"client-cert", required_argument, 0, 1024},
    {"client-key", required_argument, 0, 1025},
    {"chunked",    no_argument,       0, 1028},
    {"help",       no_argument,       0, 'h'},
    {"version",    no_argument,       0, 'V'},
    {0, 0, 0, 0}
  };
  const char *optstr = "X:H:d:F:o:OIj:c:kLvsifm:r:u:A:hVx:U:C:46T:S:b:lK:";
  char method[16] = "GET";
  char *data = NULL;
  size_t dlen = 0;
  char **uhdrs = NULL;
  int nuhdrs = 0;
  char auth[512] = {0};
  const char *ua = NULL;
  const char *range = NULL;
  const char *outfile = NULL;
  int remote_name = 0, head = 0, parallel = 1, segs = 1, insecure = 0;
  int follow = 1, silent = 0, inc_hdrs = 0, fail = 0;
  long timeout = 0;
  int color_mode = 1;
  const char *proxyarg = NULL;
  const char *proxyuser = NULL;
  const char *resume = NULL;
  const char *upload = NULL;
  const char *cookiearg = NULL;
  const char *cookiejar = NULL;
  char **formparts = NULL;
  int nform = 0;
  const char *ctype_mp = NULL;
  int ipv = 0;
  int no_decode = 0;
  int opt, i, nurls;
  Cfg cfg;
  Jb *jobs;
  int *fails;
  Pool pc;
  pthread_t *ths;
  int nt, rc = 0;

  while((opt = getopt_long(argc, argv, optstr, lopt, NULL)) != -1) {
    switch(opt) {
    case 'X':
      if(strlen(optarg) >= sizeof method) {
        fprintf(stderr, "volley: method name too long\n");
        return 1;
      }
      strcpy(method, optarg);
      break;
    case 'H':
      {
        char **nh = realloc(uhdrs, (size_t)(nuhdrs + 1) * sizeof *nh);
        if(!nh) {
          fprintf(stderr, "volley: out of memory\n");
          return 1;
        }
        uhdrs = nh;
        uhdrs[nuhdrs++] = optarg;
      }
      break;
    case 'd':
      {
        size_t ol = strlen(optarg);
        char *nd = malloc(data ? dlen + ol + 2 : ol + 1);
        if(!nd) {
          fprintf(stderr, "volley: out of memory\n");
          return 1;
        }
        if(data) {
          memcpy(nd, data, dlen);
          nd[dlen] = '&';
          memcpy(nd + dlen + 1, optarg, ol + 1);
          free(data);
          dlen += ol + 1;
        }
        else {
          memcpy(nd, optarg, ol + 1);
          dlen = ol;
        }
        data = nd;
      }
      break;
    case 'o': outfile = optarg; break;
    case 'O': remote_name = 1;   break;
    case 'I': head = 1;           break;
    case 'F':
      {
        char **nf = realloc(formparts, (size_t)(nform + 1) * sizeof *nf);
        if(!nf) {
          fprintf(stderr, "volley: out of memory\n");
          return 1;
        }
        formparts = nf;
        formparts[nform++] = optarg;
      }
      break;
    case 'j':
      parallel = atoi(optarg);
      if(parallel == 0)
        parallel = (int)sysconf(_SC_NPROCESSORS_ONLN);
      break;
    case 'c': segs = atoi(optarg); break;
    case 'k': insecure = 1;        break;
    case 'L': follow = 1;          break;
    case 1000: follow = 0;         break;
    case 'v': g_verbose = 1;       break;
    case 's': silent = 1;          break;
    case 'i': inc_hdrs = 1;        break;
    case 'm': timeout = atol(optarg); break;
    case 'f': fail = 1;            break;
    case 'r': range = optarg;      break;
    case 'u':
      if(strlen(optarg) >= sizeof auth) {
        fprintf(stderr, "volley: credentials too long\n");
        return 1;
      }
      strcpy(auth, optarg);
      break;
    case 'A': ua = optarg;         break;
    case 'x': proxyarg = optarg;   break;
    case 'U': proxyuser = optarg;  break;
    case 'C': resume = optarg;     break;
    case '4': ipv = 4;             break;
    case '6': ipv = 6;             break;
    case 'T': upload = optarg;     break;
    case 'S': snprintf(g_session, sizeof g_session, "%s", optarg); break;
    case 'b': cookiearg = optarg;  break;
    case 'l': g_listonly = 1;      break;
    case 'K': break;   /* handled by the pre-scan */
    case 1002: no_decode = 1;      break;
    case 1003: cookiejar = optarg; break;
    case 1004: g_sess_only = 1;    break;
    case 1005:
      if(!strcasecmp(optarg, "dot") || !strncmp(optarg, "dot:", 4)) {
        g_progstyle = 1;
        if(optarg[3] == ':') {
          g_dot_bytes = atoi(optarg + 4);
          if(g_dot_bytes <= 0) g_dot_bytes = 1024;
        }
      }
      else
        g_progstyle = 0;
      break;
    case 1006:
      g_limit_rate = parse_size(optarg);
      if(g_limit_rate <= 0)
        g_limit_rate = atoll(optarg);
      break;
    case 1007: g_conn_timeout = atol(optarg); break;
    case 1008: g_retries = atoi(optarg); break;
    case 1009: g_retry_all = 1; break;
    case 1010: g_retry_wait = atol(optarg); break;
    case 1011: g_netrc = 1; break;
    case 1012: g_netrc = 0; break;
    case 1013: snprintf(g_netrc_file, sizeof g_netrc_file, "%s", optarg); break;
    case 1014: g_http2 = 1; g_alpn_h2 = 1; break;
    case 1015: g_http2 = 0; g_alpn_h2 = 0; break;
    case 1016: g_recursive = 1; break;
    case 1017: g_mirror = 1; g_recursive = 1; break;
    case 1018: g_level = atoi(optarg); break;
    case 1019: snprintf(g_domains, sizeof g_domains, "%s", optarg); break;
    case 1020: g_span_hosts = 1; break;
    case 1021: snprintf(g_accept, sizeof g_accept, "%s", optarg); break;
    case 1022: snprintf(g_reject, sizeof g_reject, "%s", optarg); break;
    case 1023: snprintf(g_dprefix, sizeof g_dprefix, "%s", optarg); break;
    case 1024: snprintf(g_certfile, sizeof g_certfile, "%s", optarg); break;
    case 1025: snprintf(g_keyfile, sizeof g_keyfile, "%s", optarg); break;
    case 1028: g_chunked = 1; g_http2 = 0; g_alpn_h2 = 0; break;
    case 1001:
      if(!strcasecmp(optarg, "always")) color_mode = 2;
      else if(!strcasecmp(optarg, "never")) color_mode = 0;
      else color_mode = 1;
      break;
    case 'h': volley_help(); return 0;
    case 'V':
      printf("volley " VOLLEY_VERSION "\n");
      return 0;
    default:
      volley_help();
      return 1;
    }
  }

  /* environment proxies: only used when -x was not given explicitly.
   HTTP_PROXY (uppercase) is ignored unless the lowercase one is absent. */
  if(!proxyarg) {
    const char *e = getenv("https_proxy");
    if((!e || !*e))
      e = getenv("http_proxy");
    if((!e || !*e)) {
      e = getenv("HTTP_PROXY");
      if(!getenv("http_proxy") && e && *e) {
        proxyarg = e;
        g_proxy_env = 1;
      }
    }
    else if(e && *e) {
      proxyarg = e;
      g_proxy_env = 1;
    }
  }
  if(getenv("no_proxy"))
    snprintf(g_no_proxy, sizeof g_no_proxy, "%s", getenv("no_proxy"));
  else if(getenv("NO_PROXY"))
    snprintf(g_no_proxy, sizeof g_no_proxy, "%s", getenv("NO_PROXY"));

  /* -x/--proxy parsing */
  if(proxyarg) {
    char tmp[640];
    char *addr;
    char *at;
    int defport = 8080;
    snprintf(tmp, sizeof tmp, "%s", proxyarg);
    if(!strncasecmp(tmp, "socks5h://", 10)) {
      g_proxy.type = 2; g_proxy.s5h = 1; addr = tmp + 10; defport = 1080;
    }
    else if(!strncasecmp(tmp, "socks5://", 9)) {
      g_proxy.type = 2; g_proxy.s5h = 0; addr = tmp + 9; defport = 1080;
    }
    else if(!strncasecmp(tmp, "socks://", 8)) {
      g_proxy.type = 2; g_proxy.s5h = 0; addr = tmp + 8; defport = 1080;
    }
    else if(!strncasecmp(tmp, "socks4://", 9)) {
      fprintf(stderr, "volley: socks4 proxies are not supported\n");
      return 1;
    }
    else {
      g_proxy.type = 1; g_proxy.s5h = 0;
      if(!strncasecmp(tmp, "http://", 7))
        addr = tmp + 7;
      else if(!strncasecmp(tmp, "https://", 8))
        addr = tmp + 8;
      else
        addr = tmp;
    }
    at = strchr(addr, '@');
    if(at) {
      *at = 0;
      snprintf(g_proxy.auth, sizeof g_proxy.auth, "%s", addr);
      addr = at + 1;
    }
    if(proxyuser)
      snprintf(g_proxy.auth, sizeof g_proxy.auth, "%s", proxyuser);
    {
      char *colon = strrchr(addr, ':');
      if(colon) {
        *colon = 0;
        snprintf(g_proxy.port, sizeof g_proxy.port, "%s", colon + 1);
      }
      else
        snprintf(g_proxy.port, sizeof g_proxy.port, "%d", defport);
    }
    snprintf(g_proxy.host, sizeof g_proxy.host, "%s", addr);
    if(!g_proxy.host[0] || !g_proxy.port[0]) {
      fprintf(stderr, "volley: malformed proxy: %s\n", proxyarg);
      return 1;
    }
  }

  /* -T upload-file */
  if(upload) {
    FILE *uf;
    struct stat st;
    if(data) {
      fprintf(stderr, "volley: -T can't be combined with -d\n");
      return 1;
    }
    if(g_chunked && !strcmp(upload, "-")) {
      /* stream stdin with chunked transfer encoding */
      g_up_file = stdin;
      if(!strcmp(method, "GET"))
        strcpy(method, "PUT");
      goto upload_done;
    }
    uf = fopen(upload, "rb");
    if(!uf) {
      fprintf(stderr, "volley: can't open upload file %s: %s\n",
              upload, strerror(errno));
      return 1;
    }
    if(g_chunked) {
      g_up_file = uf;
      if(!strcmp(method, "GET"))
        strcpy(method, "PUT");
      goto upload_done;
    }
    if(fstat(fileno(uf), &st) != 0 || st.st_size > (off_t)(1LL << 31)) {
      fprintf(stderr, "volley: upload file too large or unreadable\n");
      fclose(uf);
      return 1;
    }
    data = malloc((size_t)(st.st_size > 0 ? st.st_size : 1));
    if(!data) {
      fprintf(stderr, "volley: out of memory\n");
      fclose(uf);
      return 1;
    }
    dlen = 0;
    for(;;) {
      size_t r = fread(data + dlen, 1, 65536, uf);
      dlen += r;
      if(r < 65536) {
        if(ferror(uf)) {
          fprintf(stderr, "volley: failed reading upload file\n");
          fclose(uf);
          free(data);
          data = NULL;
          return 1;
        }
        break;
      }
    }
    fclose(uf);
    if(!strcmp(method, "GET"))
      strcpy(method, "PUT");
  }
  upload_done:
  g_upload_file = upload != NULL;

  /* -b/--cookie: literal string or a cookie file */
  if(cookiearg) {
    FILE *cf = fopen(cookiearg, "r");
    g_cook_use = 1;
    g_cook_enabled = 1;
    if(cf) {
      cookie_jar_load(cookiearg);
      fclose(cf);
    }
    else {
      snprintf(g_cook_in, sizeof g_cook_in, "%s", cookiearg);
    }
  }
  if(cookiejar) {
    snprintf(g_cook_file, sizeof g_cook_file, "%s", cookiejar);
    g_cook_save = 1;
  }

  /* -F multipart form */
  if(nform) {
    static const char bchars[] =
      "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char bound[64] = "--------------------------volley";
    size_t bind = strlen(bound);
    unsigned int seed = (unsigned)(time(NULL) ^ (unsigned long)data);
    Buffer fb;
    char ctbuf[180];
    if(data) {
      free(data);
      data = NULL;
      dlen = 0;
    }
    while(bind < sizeof bound - 1) {
      bound[bind++] = bchars[rand_r(&seed) % (sizeof bchars - 1)];
    }
    bound[bind] = 0;
    memset(&fb, 0, sizeof fb);
    {
      for(int fi = 0; fi < nform; fi++) {
        const char *spec = formparts[fi];
        char name[1024], val[4096], *eq, *at, *ctype = NULL, *fname = NULL;
      b_add(&fb, "--", 2);
      b_add(&fb, bound, strlen(bound));
      b_add(&fb, "\r\n", 2);
      snprintf(name, sizeof name, "%s", spec);
      eq = strchr(name, '=');
      if(!eq) {
        fprintf(stderr, "volley: malformed -F field: %s\n", spec);
        free(fb.data);
        return 1;
      }
      *eq = 0;
      at = eq + 1;
      if(*at == '@') {
        char filep[1024], semicolon[512] = "";
        FILE *ff;
        struct stat st;
        snprintf(filep, sizeof filep, "%s", at + 1);
        {
          char *sm = strchr(filep, ';');
          if(sm) {
            snprintf(semicolon, sizeof semicolon, "%s", sm);
            *sm = 0;
          }
        }
        /* optional ;type= */
        if(semicolon[0]) {
          char *tp = strstr(semicolon, "type=");
          if(tp)
            ctype = tp + 5;
        }
        fname = strrchr(filep, '/');
        fname = fname ? fname + 1 : filep;
        ff = fopen(filep, "rb");
        if(!ff) {
          fprintf(stderr, "volley: can't open form file %s: %s\n",
                  filep, strerror(errno));
          free(fb.data);
          return 1;
        }
        fstat(fileno(ff), &st);
        b_add(&fb, "Content-Disposition: form-data; name=\"", 39);
        b_add(&fb, name, strlen(name));
        b_add(&fb, "\"; filename=\"", 13);
        b_add(&fb, fname, strlen(fname));
        b_add(&fb, "\"\r\n", 3);
        b_add(&fb, "Content-Type: ", 14);
        b_add(&fb, ctype ? ctype : "application/octet-stream",
              strlen(ctype ? ctype : "application/octet-stream"));
        b_add(&fb, "\r\n\r\n", 4);
        {
          char chunk[65536];
          size_t got;
          while((got = fread(chunk, 1, sizeof chunk, ff)) > 0)
            b_add(&fb, chunk, got);
        }
        fclose(ff);
      }
      else {
        char *sm = strchr(at, ';');
        if(sm)
          *sm = 0;
        snprintf(val, sizeof val, "%s", at);
        b_add(&fb, "Content-Disposition: form-data; name=\"", 37);
        b_add(&fb, name, strlen(name));
        b_add(&fb, "\"\r\n\r\n", 5);
        b_add(&fb, val, strlen(val));
      }
      b_add(&fb, "\r\n", 2);
    }
    }
    b_add(&fb, "--", 2);
    b_add(&fb, bound, strlen(bound));
    b_add(&fb, "--\r\n", 4);
    data = fb.data;
    dlen = fb.len;
    snprintf(ctbuf, sizeof ctbuf, "multipart/form-data; boundary=%s", bound);
    {
      char *nd = malloc(strlen(ctbuf) + 1);
      if(nd)
        strcpy(nd, ctbuf);
      ctype_mp = nd;
    }
    if(!strcmp(method, "GET"))
      strcpy(method, "POST");
  }

  nurls = argc - optind;
  if(nurls < 1 || nurls > VOLLEY_MAX_URLS) {
    if(nurls < 1)
      fprintf(stderr, "volley: no URL given (try -h)\n");
    else
      fprintf(stderr, "volley: too many URLs (max %d)\n", VOLLEY_MAX_URLS);
    return 1;
  }
  if(outfile && remote_name) {
    fprintf(stderr, "volley: you can't use both -o and -O!\n");
    return 1;
  }
  if(outfile && nurls > 1) {
    fprintf(stderr, "volley: -o only works with a single URL (use -O or none)\n");
    return 1;
  }
  if(resume && !outfile && !remote_name) {
    fprintf(stderr, "volley: -C/--continue-at needs -o or -O to resume to a file\n");
    return 1;
  }
  if(upload && nurls > 1) {
    fprintf(stderr, "volley: -T only works with a single URL\n");
    return 1;
  }
  if(data && !strcmp(method, "GET"))
    strcpy(method, "POST");
  if(ipv == 4)
    g_af = 4;
  else if(ipv == 6)
    g_af = 6;

  set_color(color_mode);
  g_timeout = timeout;
  if(g_conn_timeout > 0 && g_timeout > 0 && g_conn_timeout > g_timeout)
    g_conn_timeout = g_timeout;
  if((!ua || !ua[0]) && g_conf_ua)
    ua = g_conf_ua;
  if(g_nconfh > 0) {
    char **nh = realloc(uhdrs, (size_t)(nuhdrs + g_nconfh) * sizeof *nh);
    if(!nh) {
      fprintf(stderr, "volley: out of memory\n");
      return 1;
    }
    uhdrs = nh;
    for(int hx = 0; hx < g_nconfh; hx++)
      uhdrs[nuhdrs++] = g_conf_hdrs[hx];
  }

  /* -S/--session: bind to the first URL's host, load stored headers+cookies,
     then re-apply what the CLI/config did not override explicitly. */
  if(g_session[0]) {
    Url su;
    if(parse_url(argv[optind], &su) == 0) {
      sess_resolve(g_session, su.host, su.port);
      sess_load();
      for(int i = 0; i < g_nsessh; i++) {
        if(!g_sess_hdrs[i] || sess_hdr_exists(uhdrs, nuhdrs, g_sess_hdrs[i]))
          continue;
        {
          char **nh = realloc(uhdrs, (size_t)(nuhdrs + 1) * sizeof *nh);
          if(!nh) {
            fprintf(stderr, "volley: out of memory\n");
            return 1;
          }
          uhdrs = nh;
        }
        uhdrs[nuhdrs++] = strdup(g_sess_hdrs[i]);
      }
    }
  }
  if(g_sess_active)
    for(int i = 0; i < nuhdrs; i++)
      sess_hdr_add(uhdrs[i]);

  if(g_netrc_file[0])
    setenv("NETRC", g_netrc_file, 1);
  if(engine_start() != 0) {
    fprintf(stderr, "volley: failed to initialize TLS\n");
    return 1;
  }

  memset(&cfg, 0, sizeof cfg);
  strcpy(cfg.method, method);
  cfg.body = data;
  cfg.body_len = dlen;
  cfg.uhdrs = uhdrs;
  cfg.nuhdrs = nuhdrs;
  snprintf(cfg.auth, sizeof cfg.auth, "%s", auth);
  cfg.useragent = ua;
  cfg.parallel = parallel;
  cfg.segs = segs;
  cfg.insecure = insecure;
  cfg.follow = follow;
  cfg.silent = silent;
  cfg.include_hdrs = inc_hdrs;
  cfg.fail_on_http = fail;
  cfg.range = range;
  cfg.head = head;
  cfg.ipv = ipv;
  cfg.resume_str = resume;
  cfg.resume_off = (resume && strcmp(resume, "-")) ? atoll(resume) : -1;
  cfg.ctype = upload ? "application/octet-stream" : ctype_mp;
  cfg.no_decode = no_decode;
  cfg.chunked = g_chunked;
  cfg.up_file = g_up_file;
  cfg.urls = &argv[optind];
  cfg.nurls = nurls;

  jobs = calloc((size_t)nurls, sizeof(Jb));
  if(!jobs) {
    fprintf(stderr, "volley: out of memory\n");
    return 1;
  }
  for(i = 0; i < nurls; i++) {
    jobs[i].url = cfg.urls[i];
    if(parse_url(cfg.urls[i], &jobs[i].u) != 0) {
      fprintf(stderr, "volley: malformed URL: %s\n", cfg.urls[i]);
      return 1;
    }
    if(remote_name) {
      const char *p = jobs[i].u.path;
      const char *last = strrchr(p, '/');
      const char *name = last ? last + 1 : p;
      size_t nlen = strcspn(name, "?#");
      if(!nlen) {
        snprintf(jobs[i].save_path, sizeof jobs[i].save_path, "index.html");
      }
      else {
        snprintf(jobs[i].save_path,
                 sizeof jobs[i].save_path < nlen + 1 ?
                   sizeof jobs[i].save_path : nlen + 1, "%s", name);
      }
    }
    else if(outfile) {
      snprintf(jobs[i].save_path, sizeof jobs[i].save_path, "%s", outfile);
    }
  }

  fails = calloc((size_t)nurls, sizeof(int));
  ths = malloc((size_t)(parallel > nurls ? nurls : parallel) *
               sizeof(pthread_t));
  if(!fails || !ths) {
    fprintf(stderr, "volley: out of memory\n");
    return 1;
  }

  if(g_recursive || g_mirror) {
    rc = mirror_engine(&cfg, jobs, nurls);
    free(fails);
    free(ths);
    if(g_cook_save && g_cook_file[0])
      cookie_jar_save(g_cook_file);
    if(g_sess_active)
      sess_save();
    if(g_up_file && g_up_file != stdin)
      fclose(g_up_file);
    engine_cleanup();
    free(jobs);
    free(uhdrs);
    free(data);
    return rc;
  }

  memset(&pc, 0, sizeof pc);
  pc.cfg = &cfg;
  pc.jobs = jobs;
  pc.njobs = nurls;
  pc.next = 0;
  pc.fails = fails;
  pthread_mutex_init(&pc.qmu, NULL);

  nt = parallel > nurls ? nurls : (parallel >= 1 ? parallel : 1);
  for(i = 0; i < nt; i++)
    pthread_create(&ths[i], NULL, job_worker, &pc);
  for(i = 0; i < nt; i++)
    pthread_join(ths[i], NULL);

  for(i = 0; i < nurls; i++)
    if(fails[i])
      rc = 1;

  if(g_cook_save && g_cook_file[0])
    cookie_jar_save(g_cook_file);
  if(g_sess_active)
    sess_save();
  if(g_up_file && g_up_file != stdin)
    fclose(g_up_file);

  engine_cleanup();

  free(jobs);
  free(fails);
  free(ths);
  free(uhdrs);
  free(data);
  return rc;
}
#endif /* !VOLLEY_LIB */
