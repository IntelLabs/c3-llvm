#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "c3/malloc/cc_globals.h"

void *c3_memcpy(char *dst, char *src, size_t n) {
  // malloc/cc_globals.h:cc_icv_memcpy
  // fprintf(stderr, "[c3 runtime] in custom memcpy (REP MOVSB)\n");
  return cc_icv_memcpy(dst, src, n);
}

void *c3_memcpy_permissive(char *dst, char *src, size_t n) {
  // malloc/cc_globals.h:cc_icv_memcpy
  // fprintf(stderr, "[c3 runtime] in custom permissive memcpy (REP MOVSB)\n");
  return cc_icv_memcpy_permissive(dst, src, n);
}

void *c3_memmove(void *dst, const void *src, size_t n) {
  // malloc/cc_globals.h:cc_icv_memmove
  // fprintf(stderr, "[c3 runtime] in custom memmove (REP MOVSB)\n");
  return cc_icv_memmove(dst, src, n);
}

void *c3_memset(void *str, int c, size_t n) {
  // fprintf(stderr, "[c3 runtime] in memset\n");
  return memset(str, c, n);
}
