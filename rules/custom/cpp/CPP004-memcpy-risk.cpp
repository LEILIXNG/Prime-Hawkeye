void bad(char *dst, const char *src, unsigned long length) {
  // ruleid: CPP004
  memcpy(dst,
         src,
         length);
}

void good() {
  char dst[8];
  const char *src = "source";
  // ok: CPP004
  memcpy(dst, src, sizeof(dst));
  // ok: CPP004
  memcpy(dst, src, 8);
  // ok: CPP004
  const char *text = "memcpy(dst, src, length)";
  // ok: CPP004
  object.memcpy();
}

void definite_overflow(const char *src) {
  char dst[8];
  // ruleid: CPP004
  memcpy(dst, src, 9);
}

void memmove_cases(const char *src) {
  char safe_dst[8];
  // ok: CPP004
  memmove(safe_dst, src, 8);
  char unsafe_dst[8];
  // ruleid: CPP004
  memmove(unsafe_dst, src, 9);
}

void strncpy_cases(const char *src) {
  char safe_dst[8];
  // ok: CPP004
  strncpy(safe_dst, src, 8);
  char unsafe_dst[8];
  // ruleid: CPP004
  strncpy(unsafe_dst, src, 9);
}
