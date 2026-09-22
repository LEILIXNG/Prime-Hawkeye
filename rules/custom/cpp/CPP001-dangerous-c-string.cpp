void bad(char *dst, const char *src) {
  // ruleid: CPP001
  std::strcat(dst, src);
  // ruleid: CPP001
  sprintf(dst,
          "%s", src);
}

void good() {
  // ok: CPP001
  // strcat(dst, src);
  // ok: CPP001
  const char *text = "strcat(dst, src)";
  // ok: CPP001
  int strcat = 1;
  // ok: CPP001
  object.strcat();
}
