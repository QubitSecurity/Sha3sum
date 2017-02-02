#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>

#include "keccak_hash.h"

void print_usage(const char *argv)
{
  fprintf(stderr, "Usage:\n", argv);
  fprintf(stderr, "sha3: %s --sha3 bits [e.g. 224, 256, 384, 512] file [file2]...\n", argv);
  fprintf(stderr, "shake: %s --shake bits [e.g. 128 or 256] file [file2]...\n", argv);
}

int main(int argc, char *argv[])
{
  keccak_hash_state ctx;
  static uint8_t buf[65536];
  int j = 3;
  int i;
  FILE *fp;
  struct stat stbuf;
  size_t ret;
  static uint8_t spongeout[100];
  static uint8_t spongehex[200];
  static const uint8_t hexval[16] = "0123456789abcdef";
  long bits;
  char *endptr;
  uint8_t delimitedSuffix;

  if (argc < 2) {
    print_usage(argv[0]);
    return 1;
  }

  /* check instance */
  if(strcmp("--sha3", argv[1]) == 0){
    delimitedSuffix = SCRYPT_SUFFIX_SHA3;
  }
  else if(strcmp("--shake", argv[1]) == 0){
    delimitedSuffix = SCRYPT_SUFFIX_SHAKE;
  }
  else{
    fprintf(stderr, "hash instance is missing.\n");
    print_usage(argv[0]);
    return 1;
  }

  errno = 0;
  bits = strtol(argv[2], &endptr, 10);
  if (errno || argv[2] == endptr || bits < 64 || bits > 736) {
    fprintf(stderr, "%s: bit's out of boundary\n", argv[0]);
    return 1;
  }
  setbuf(stdout, NULL);

  while (j < argc) {
    if (!strcmp(argv[j], "-")) {
      fp = stdin;
    } else {
      fp = fopen(argv[j], "rb");
    }
    if (fp == NULL) {
      fprintf(stderr, "%s: %s\n", argv[j], strerror(errno));
    } else {
      if ((fp != stdin) && (fstat(fileno(fp), &stbuf) == 0) &&
          (S_ISDIR(stbuf.st_mode))) {
        fprintf(stderr, "%s: Is a directory\n", argv[j]);
      } else {
        if (fp != stdin) setbuf(fp, NULL);
        if (keccak_hash_init(&ctx, keccak_strength_to_rate(bits), delimitedSuffix) == false) {
          fprintf(stderr, "%s: keccak_hash_init failed\n", argv[0]);
          return 1;
        }
        do {
          ret = fread(buf, 1, sizeof(buf), fp);
          keccak_hash_update(&ctx, buf, ret);
        } while (ret > 0);
        keccak_hash_finish(&ctx, spongeout, bits/8);
        for (i = 0; i < bits/8; i++) {
          spongehex[i*2+0] = hexval[spongeout[i] >> 4];
          spongehex[i*2+1] = hexval[spongeout[i] & 15];
        }
        spongehex[i*2] = 0;
        fprintf(stdout, "%s %s\n", spongehex, argv[j]);
      }
      if (fp != stdin) fclose(fp);
    }
    j++;
  }
  return 0;
}
