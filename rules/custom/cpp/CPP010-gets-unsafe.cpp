void bad(char *dst) {
  // ruleid: CPP010
  gets(dst);
}

void good() {
  // ok: CPP010
  // gets(dst);
  // ok: CPP010
  const char *text = "gets(dst)";
  // ok: CPP010
  int gets = 1;
  // ok: CPP010
  object.gets();
}
