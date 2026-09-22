void bad() {
  char dst[8];
  char src[9];
  // ruleid: CPP009
  strcpy(dst, src);
}

void good() {
  char dst[8];
  char src[8];
  // ok: CPP009
  strcpy(dst, src);
  // ok: CPP009
  const char *text = "strcpy(dst, src)";
  // ok: CPP009
  int strcpy = 1;
  // ok: CPP009
  object.strcpy();
}
