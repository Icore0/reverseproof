/* Toy "protected app": a licence check and an embedded API key.
 * Built four ways by test/toy.test.js to measure what a reverse engineer actually recovers. */
#include <stdio.h>
#include <string.h>
#ifdef DENY_ATTACH
#include <sys/ptrace.h>
#endif

#ifdef XOR_KEY
/* "sk_live_TOYSECRET_DO_NOT_USE_1234567890" ^ 0x5A, decoded at runtime */
static volatile unsigned char blob[] = { XOR_BLOB };
static void reveal(char *out) { for (size_t i = 0; i < sizeof blob; i++) out[i] = blob[i] ^ XOR_KEY; out[sizeof blob] = 0; }
#else
static const char SECRET[] = "sk_live_TOYSECRET_DO_NOT_USE_1234567890";
static void reveal(char *out) { strcpy(out, SECRET); }
#endif

int check_license(const char *k) { return strcmp(k, "LICENSE-ABCD-1234") == 0; }

int main(int argc, char **argv) {
  char key[64];
#ifdef DENY_ATTACH
  ptrace(PT_DENY_ATTACH, 0, 0, 0); /* macOS: kernel kills the process if a debugger is/gets attached */
#endif
  reveal(key);
  if (argc > 1 && check_license(argv[1])) puts("pro unlocked");
  printf("key length %d\n", (int)strlen(key));
  return 0;
}
