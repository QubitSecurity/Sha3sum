#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>   /* for __NR_getrandom */
#include <errno.h>

#include "keccak_hash.h"
#include "keccakf_hash.h"

static const uint8_t delimitedSigmaEnd = KECCAK_SPONGE_SIGMAEND;
static const uint8_t delimitedSigmaEndLast = KECCAK_SPONGE_SIGMAEND_LAST;

static bool system_random_bytes(void *p, size_t n)
{
	if (!n) return true;

#if defined(__NR_getrandom) && defined(__linux__)
	long ret;

	do {
		/* <=256 byte requests always succeed */
		ret = syscall(__NR_getrandom, p, n, 0, 0, 0, 0);
	} while ((ret == -1) && (errno == EINTR));
	return (ret == n);
#else
	static FILE *frandom; /* locking */

	if (frandom == NULL) {
		frandom = fopen("/dev/urandom", "rb");
		if (frandom == NULL) {
			return false;
		}
		setbuf(frandom, NULL);
	}
	if (fread(p, 1, n, frandom) != n) {
		fclose(frandom);
		frandom = NULL;
		return false;
	}
	return true;
#endif
}

static void keccak_absorb(keccak_hash_state *S, const uint8_t *in) {
	size_t i;
	uint64_t *s = S->state;

	/* absorb input */
	for (i = 0; i < S->rate / 8; i++, in += 8)
#ifdef CPU_LE
		s[i] ^= *(uint64_t*)in;
#else
		s[i] ^= U8TO64_LE(in);
#endif
	keccakf(s, 24);
}

void keccak_hash_update(keccak_hash_state *S, const uint8_t *in, size_t inlen) {
	size_t want;

	if (!inlen) return;
	/* handle the previous data */
	if (S->leftover) {
		want = (S->rate - S->leftover);
		want = min(want, inlen);
		memcpy(S->buffer + S->leftover, in, want);
		S->leftover += want;
		if (S->leftover < S->rate)
			return;
		in += want;
		inlen -= want;
		keccak_absorb(S, S->buffer);
	}

	/* handle the current data */
	while (inlen >= S->rate) {
		keccak_absorb(S, in);
		in += S->rate;
		inlen -= S->rate;
	}

	/* handle leftover data */
	S->leftover = inlen;
	if (S->leftover)
		memcpy(S->buffer, in, S->leftover);
}

void keccak_hash_finish(keccak_hash_state *S, uint8_t *hash,
			size_t outputbytelen) {
	size_t blocksize;

	S->buffer[S->leftover] = S->delimitedSuffix;
	memset(S->buffer + (S->leftover + 1), 0, S->rate - (S->leftover + 1));
	S->buffer[S->rate - 1] |= 0x80;
	keccak_absorb(S, S->buffer);

	while (outputbytelen > 0) {
		blocksize = min(outputbytelen, S->rate);
#ifdef CPU_LE
		memcpy(hash, S->state, blocksize);
#else
		for (size_t i = 0; i < blocksize; i += 8) {
			U64TO8_LE(&hash[i], S->state[i / 8]);
		}
#endif
		hash += blocksize;
		outputbytelen -= blocksize;
		if (outputbytelen > 0)
			keccakf(S->state, 24);
	}
}

static inline void keccak_XORBytes(void *state, const uint8_t *data,
				   size_t offset, size_t length)
{
	size_t i;
	uint8_t *p = state;

	for(i = 0; i < length; i++)
		p[offset+i] ^= data[i];
}

static inline void keccak_COPYBytes(void *state, uint8_t *data,
				    size_t offset, size_t length)
{
	uint8_t *p = state + offset;

	memcpy(data, p, length);
}

bool keccak_duplex(keccak_duplex_state *S, const uint8_t *sigmaBegin,
		   size_t sigmaBeginByteLen, uint8_t *Z, size_t ZByteLen)
{
	const size_t rho_max = S->rate - 1;

	if ((sigmaBeginByteLen > (SIZE_MAX - S->byteInputIndex)) ||
	    ((S->byteInputIndex + sigmaBeginByteLen) > rho_max)) {
		return false;
	}
	// The output length must not be greater than the rate
	if (ZByteLen > S->rate) {
		return false;
	}

	keccak_XORBytes(S->state, sigmaBegin,
			S->byteInputIndex, sigmaBeginByteLen);
	keccak_XORBytes(S->state, &delimitedSigmaEnd,
			S->byteInputIndex + sigmaBeginByteLen, 1);
	keccak_XORBytes(S->state, &delimitedSigmaEndLast, S->rate - 1, 1);
	keccakf(S->state, 24);
	S->byteInputIndex = 0;
	S->byteOutputIndex = ZByteLen;
	if (Z) memcpy(Z, S->state, ZByteLen);
	return true;
}

static void keccak_duplex_pad(keccak_duplex_state *S)
{
	keccak_XORBytes(S->state, &delimitedSigmaEnd, S->byteInputIndex, 1);
	keccak_XORBytes(S->state, &delimitedSigmaEndLast, S->rate - 1, 1);
	keccakf(S->state, 24);
	S->byteInputIndex = 0;
	S->byteOutputIndex = 0;
}

void keccak_duplex_feed(keccak_duplex_state *S, uint8_t *sigmaBegin,
			size_t sigmaBeginByteLen)
{
	const size_t rho_max = S->rate - 1;

	if (!sigmaBeginByteLen) return;
	while (sigmaBeginByteLen > 0) {
		size_t want = min(sigmaBeginByteLen,
				  rho_max - S->byteInputIndex);
		if (!want) {
			keccak_duplex_pad(S);
			continue;
		}
		keccak_XORBytes(S->state, sigmaBegin, S->byteInputIndex, want);
		sigmaBegin += want;
		sigmaBeginByteLen -= want;
		S->byteInputIndex += want;
	}
	/* force fetch to permute state */
	S->byteOutputIndex = S->rate;
}

void keccak_duplex_fetch(keccak_duplex_state *S, uint8_t *out, size_t outlen)
{
	while (outlen > 0) {
		size_t want = min(outlen, S->rate - S->byteOutputIndex);
		if (!want) {
			keccak_duplex_pad(S);
			continue;
		}
		keccak_COPYBytes(S->state, out, S->byteOutputIndex, want);
		out += want;
		outlen -= want;
		S->byteOutputIndex += want;
	}
}

void keccak_duplex_forget(keccak_duplex_state *S)
{
        keccak_duplex_pad(S);
	S->byteInputIndex = S->rate - 1;
	memset(S->state, 0, S->rate - 1);
	keccak_duplex_pad(S);
	S->byteOutputIndex = S->rate;
}

bool keccak_duplex_reseed(keccak_duplex_state *S)
{
	uint8_t sysrand[S->rate - 1];
	size_t needed = (SCRYPT_KECCAK_F/8) / S->rate;

	while (needed--) {
		keccak_duplex_pad(S);
		if (system_random_bytes(sysrand, sizeof(sysrand)) == false) {
			return false;
		}
		keccak_duplex_feed(S, sysrand, sizeof(sysrand));
	}
	return true;
}
