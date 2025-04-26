// md5_sse.h
#include <iostream>
#include <string>
#include <cstring>
#include <emmintrin.h>
#include <tmmintrin.h>
#include <smmintrin.h>

using namespace std;
#ifndef MD5_SSE_H
#define MD5_SSE_H

typedef unsigned char Byte;
typedef unsigned int bit32;

#define s11 7
#define s12 12
#define s13 17
#define s14 22
#define s21 5
#define s22 9
#define s23 14
#define s24 20
#define s31 4
#define s32 11
#define s33 16
#define s34 23
#define s41 6
#define s42 10
#define s43 15
#define s44 21

// SSE implementations of basic MD5 functions
#define SSE_F(x, y, z) \
    _mm_or_si128(_mm_and_si128((x), (y)), _mm_and_si128(_mm_andnot_si128((x), (z)))
#define SSE_G(x, y, z) \
    _mm_or_si128(_mm_and_si128((x), (z)), _mm_and_si128(_mm_andnot_si128((z)), (y)))
#define SSE_H(x, y, z) \
    _mm_xor_si128(_mm_xor_si128((x), (y)), (z))
#define SSE_I(x, y, z) \
    _mm_xor_si128((y), _mm_or_si128((x), _mm_andnot_si128((z), _mm_set1_epi32(-1))))

#define SSE_ROTATELEFT(num, n) \
    _mm_or_si128( \
        _mm_slli_epi32((num), (n)), \
        _mm_srli_epi32((num), 32-(n)) \
    )

#define SSE_FF(a, b, c, d, x, s, ac) { \
    __m128i t = _mm_add_epi32(SSE_F((b), (c), (d)), _mm_add_epi32((x), _mm_set1_epi32(ac))); \
    (a) = _mm_add_epi32((a), t); \
    (a) = SSE_ROTATELEFT((a), (s)); \
    (a) = _mm_add_epi32((a), (b)); \
}

#define SSE_GG(a, b, c, d, x, s, ac) { \
    __m128i t = _mm_add_epi32(SSE_G((b), (c), (d)), _mm_add_epi32((x), _mm_set1_epi32(ac))); \
    (a) = _mm_add_epi32((a), t); \
    (a) = SSE_ROTATELEFT((a), (s)); \
    (a) = _mm_add_epi32((a), (b)); \
}

#define SSE_HH(a, b, c, d, x, s, ac) { \
    __m128i t = _mm_add_epi32(SSE_H((b), (c), (d)), _mm_add_epi32((x), _mm_set1_epi32(ac))); \
    (a) = _mm_add_epi32((a), t); \
    (a) = SSE_ROTATELEFT((a), (s)); \
    (a) = _mm_add_epi32((a), (b)); \
}

#define SSE_II(a, b, c, d, x, s, ac) { \
    __m128i t = _mm_add_epi32(SSE_I((b), (c), (d)), _mm_add_epi32((x), _mm_set1_epi32(ac))); \
    (a) = _mm_add_epi32((a), t); \
    (a) = SSE_ROTATELEFT((a), (s)); \
    (a) = _mm_add_epi32((a), (b)); \
}

void SSE_MD5Hash(string input, bit32 *state);

#endif