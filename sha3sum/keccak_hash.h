#ifndef keccak_hash_h
#define keccak_hash_h

#include <stdbool.h>

/* determine compiler */
#if defined(_MSC_VER)
	#define COMPILER_MSVC_VS6       120000000
	#define COMPILER_MSVC_VS6PP     121000000
	#define COMPILER_MSVC_VS2002    130000000
	#define COMPILER_MSVC_VS2003    131000000
	#define COMPILER_MSVC_VS2005    140050727
	#define COMPILER_MSVC_VS2008    150000000
	#define COMPILER_MSVC_VS2008SP1 150030729
	#define COMPILER_MSVC_VS2010    160000000
	#define COMPILER_MSVC_VS2010SP1 160040219
	#define COMPILER_MSVC_VS2012RC  170000000
	#define COMPILER_MSVC_VS2012    170050727

	#if _MSC_FULL_VER > 100000000
		#define COMPILER_MSVC (_MSC_FULL_VER)
	#else
		#define COMPILER_MSVC (_MSC_FULL_VER * 10)
	#endif

	#if ((_MSC_VER == 1200) && defined(_mm_free))
		#undef COMPILER_MSVC
		#define COMPILER_MSVC COMPILER_MSVC_VS6PP
	#endif

	#pragma warning(disable : 4127) /* conditional expression is constant */
	#pragma warning(disable : 4100) /* unreferenced formal parameter */

	#define _CRT_SECURE_NO_WARNINGS
	#include <float.h>
	#include <stdlib.h> /* _rotl */
	#include <intrin.h>

	typedef unsigned char uint8_t;
	typedef unsigned short uint16_t;
	typedef unsigned int uint32_t;
	typedef signed int int32_t;
	typedef unsigned __int64 uint64_t;
	typedef signed __int64 int64_t;

	#define ROTL32(a,b) _rotl(a,b)
	#define ROTR32(a,b) _rotr(a,b)
	#define ROTL64(a,b) _rotl64(a,b)
	#define ROTR64(a,b) _rotr64(a,b)
	#undef NOINLINE
	#define NOINLINE __declspec(noinline)
	#undef NORETURN
	#define NORETURN
	#undef INLINE
	#define INLINE __forceinline
	#undef FASTCALL
	#define FASTCALL __fastcall
	#undef CDECL
	#define CDECL __cdecl
	#undef STDCALL
	#define STDCALL __stdcall
	#undef NAKED
	#define NAKED __declspec(naked)
	#define ALIGN(n) __declspec(align(n))
#endif
#if defined(__ICC)
	#define COMPILER_INTEL
#endif
#if defined(__GNUC__)
	#if (__GNUC__ >= 3)
		#define COMPILER_GCC_PATCHLEVEL __GNUC_PATCHLEVEL__
	#else
		#define COMPILER_GCC_PATCHLEVEL 0
	#endif
	#define COMPILER_GCC (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + COMPILER_GCC_PATCHLEVEL)
	#define ROTL32(a,b) (((a) << (b)) | ((a) >> (32 - b)))
	#define ROTR32(a,b) (((a) >> (b)) | ((a) << (32 - b)))
	#define ROTL64(a,b) (((a) << (b)) | ((a) >> (64 - b)))
	#define ROTR64(a,b) (((a) >> (b)) | ((a) << (64 - b)))
	#undef NOINLINE
	#if (COMPILER_GCC >= 30000)
		#define NOINLINE __attribute__((noinline))
	#else
		#define NOINLINE
	#endif
	#undef NORETURN
	#if (COMPILER_GCC >= 30000)
		#define NORETURN __attribute__((noreturn))
	#else
		#define NORETURN
	#endif
	#undef INLINE
	#if (COMPILER_GCC >= 30000)
		#define INLINE __attribute__((always_inline))
	#else
		#define INLINE inline
	#endif
	#undef FASTCALL
	#if (COMPILER_GCC >= 30400)
		#define FASTCALL __attribute__((fastcall))
	#else
		#define FASTCALL
	#endif
	#undef CDECL
	#define CDECL __attribute__((cdecl))
	#undef STDCALL
	#define STDCALL __attribute__((stdcall))
	#define ALIGN(n) __attribute__((aligned(n)))
	#include <stdint.h>
#endif
#if defined(__MINGW32__) || defined(__MINGW64__)
	#define COMPILER_MINGW
#endif
#if defined(__PATHCC__)
	#define COMPILER_PATHCC
#endif

#define OPTIONAL_INLINE
#if defined(OPTIONAL_INLINE)
	#undef OPTIONAL_INLINE
	#define OPTIONAL_INLINE INLINE
#else
	#define OPTIONAL_INLINE
#endif

#define CRYPTO_FN NOINLINE STDCALL

/* endian */

#if ((defined(__BYTE_ORDER) && defined(__LITTLE_ENDIAN) && (__BYTE_ORDER == __LITTLE_ENDIAN)) || \
	 (defined(BYTE_ORDER) && defined(LITTLE_ENDIAN) && (BYTE_ORDER == LITTLE_ENDIAN)) || \
	 (defined(CPU_X86) || defined(CPU_X86_64)) || \
	 (defined(vax) || defined(MIPSEL) || defined(_MIPSEL)))
#define CPU_LE
#elif ((defined(__BYTE_ORDER) && defined(__BIG_ENDIAN) && (__BYTE_ORDER == __BIG_ENDIAN)) || \
	   (defined(BYTE_ORDER) && defined(BIG_ENDIAN) && (BYTE_ORDER == BIG_ENDIAN)) || \
	   (defined(CPU_SPARC) || defined(CPU_PPC) || defined(mc68000) || defined(sel)) || defined(_MIPSEB))
#define CPU_BE
#else
	/* unknown endian! */
#endif

#define U8TO32_BE(p)                                            \
	(((uint32_t)((p)[0]) << 24) | ((uint32_t)((p)[1]) << 16) |  \
	 ((uint32_t)((p)[2]) <<  8) | ((uint32_t)((p)[3])      ))

#define U8TO32_LE(p)                                            \
	(((uint32_t)((p)[0])      ) | ((uint32_t)((p)[1]) <<  8) |  \
	 ((uint32_t)((p)[2]) << 16) | ((uint32_t)((p)[3]) << 24))

#define U32TO8_BE(p, v)                                           \
	(p)[0] = (uint8_t)((v) >> 24); (p)[1] = (uint8_t)((v) >> 16); \
	(p)[2] = (uint8_t)((v) >>  8); (p)[3] = (uint8_t)((v)      );

#define U32TO8_LE(p, v)                                           \
	(p)[0] = (uint8_t)((v)      ); (p)[1] = (uint8_t)((v) >>  8); \
	(p)[2] = (uint8_t)((v) >> 16); (p)[3] = (uint8_t)((v) >> 24);

#define U8TO64_BE(p)                                                  \
	(((uint64_t)U8TO32_BE(p) << 32) | (uint64_t)U8TO32_BE((p) + 4))

#define U8TO64_LE(p)                                                  \
	(((uint64_t)U8TO32_LE(p)) | ((uint64_t)U8TO32_LE((p) + 4) << 32))

#define U64TO8_BE(p, v)                        \
	U32TO8_BE((p),     (uint32_t)((v) >> 32)); \
	U32TO8_BE((p) + 4, (uint32_t)((v)      ));

#define U64TO8_LE(p, v)                        \
	U32TO8_LE((p),     (uint32_t)((v)      )); \
	U32TO8_LE((p) + 4, (uint32_t)((v) >> 32));

#define U32_SWAP(v) {                                               \
	(v) = (((v) << 8) & 0xFF00FF00 ) | (((v) >> 8) & 0xFF00FF );\
    (v) = ((v) << 16) | ((v) >> 16);                                \
}

#define U64_SWAP(v) {                                                                          \
	(v) = (((v) <<  8) & 0xFF00FF00FF00FF00ull ) | (((v) >>  8) & 0x00FF00FF00FF00FFull ); \
	(v) = (((v) << 16) & 0xFFFF0000FFFF0000ull ) | (((v) >> 16) & 0x0000FFFF0000FFFFull ); \
    (v) = ((v) << 32) | ((v) >> 32);                                                           \
}

#if !defined(asm_calling_convention)
#define asm_calling_convention
#endif

#define min(x,y) ({             \
        typeof(x) _min1 = (x);     \
        typeof(y) _min2 = (y);     \
        (void) (&_min1 == &_min2);    \
        _min1 < _min2 ? _min1 : _min2; })

#define SCRYPT_KECCAK_F 1600
#define SCRYPT_SUFFIX_SHAKE 0x1F
#define SCRYPT_SUFFIX_SHA3 0x06

typedef struct keccak_hash_state_t {
	uint64_t ALIGN(32) state[SCRYPT_KECCAK_F / 64];
	uint8_t ALIGN(32) buffer[SCRYPT_KECCAK_F / 8];
        size_t leftover;
	size_t rate;
	uint8_t delimitedSuffix;
} keccak_hash_state;

/* Assumes rate+capacity=1600 */
static inline bool keccak_hash_init(keccak_hash_state *S, size_t rate, uint8_t
				    delimitedSuffix) {
	/* %64 only because xoring is done 64 bits at a time */
	if (rate == 0 || rate > SCRYPT_KECCAK_F || ((rate % 64) != 0) ||
	    (delimitedSuffix & 0x80)) return false;
	memset(S->state, 0, sizeof(S->state));
	memset(S->buffer, 0, sizeof(S->buffer));
	S->leftover = 0;
        S->rate = rate / 8;
	S->delimitedSuffix = delimitedSuffix;
	return true;
}
void keccak_hash_update(keccak_hash_state *S, const uint8_t *in, size_t inlen);
/* outputbytelen must be divisible by 8 */
void keccak_hash_finish(keccak_hash_state *S, uint8_t *hash, size_t outputbytelen);

#define KECCAK_SPONGE_SIGMAEND (0x01)
#define KECCAK_SPONGE_SIGMAEND_LAST (0x80)

typedef struct keccak_duplex_state_t {
	uint64_t ALIGN(32) state[SCRYPT_KECCAK_F / 64];
	size_t rate;
        size_t byteInputIndex;
        size_t byteOutputIndex;
} keccak_duplex_state;

/* Returns strength (e.g., security level), 256 returns 1088 */
static inline size_t keccak_strength_to_rate(size_t strength)
{
	if (strength > ((SCRYPT_KECCAK_F / 2) - 64)) return 0;
	if (strength < 64) return 0;
	return (SCRYPT_KECCAK_F - (strength * 2));
}

/* Assumes rate+capacity=1600 */
static inline bool keccak_duplex_init(keccak_duplex_state *S, size_t rate) {
	if (rate < 64 || rate > (SCRYPT_KECCAK_F-64) || ((rate % 64) != 0)) return false;
	memset(S->state, 0, sizeof(S->state));
	S->rate = rate / 8;
	S->byteInputIndex = 0;
	S->byteOutputIndex = rate / 8;
	return true;
}
bool keccak_duplex(keccak_duplex_state *S, const uint8_t *sigmaBegin,
		   size_t sigmaBeginByteLen, uint8_t *Z, size_t ZByteLen);
void keccak_duplex_feed(keccak_duplex_state *S, uint8_t *sigmaBegin,
			size_t sigmaBeginByteLen);
void keccak_duplex_fetch(keccak_duplex_state *S, uint8_t *out, size_t outlen);
bool keccak_duplex_reseed(keccak_duplex_state *S);
void keccak_duplex_forget(keccak_duplex_state *S);

#endif
