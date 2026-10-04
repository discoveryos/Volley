/* smoke.c - verify that other software can link libvolley and fetch. */
#include "libvolley.h"
#include <stdio.h>
#include <string.h>

/* tiny adapter: header exposes struct volley_opts/volley_result. */
static int fetch_once(const char *url)
{
  struct volley_opts o;
  struct volley_result r;
  char err[1024] = "";
  memset(&o, 0, sizeof o);
  o.url = url;
  if(volley_fetch(&o, &r) != 0) {
    fprintf(stderr, "fetch FAIL: %s\n", err[0] ? err : r.err);
    return -1;
  }
  printf("ok status=%d bytes=%lld/%lld body_len=%zu final=%s err=%s\n",
         r.status, r.bytes, r.total, r.body_len,
         r.final_url[0] ? r.final_url : "-", r.err);
  volley_result_free(&r);
  return 0;
}

int main(int argc, char **argv)
{
  const char *url = argc > 1 ? argv[1] : "https://nghttp2.org";
  volley_global_init();
  printf("version=%s\n", volley_version());
  int rc = fetch_once(url);
  volley_global_cleanup();
  return rc;
}
