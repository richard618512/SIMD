// md5_avx2.cpp
#include "md5_avx2.h"
#include <iomanip>
#include <assert.h>
#include <chrono>

using namespace std;
using namespace chrono;

Byte *StringProcess(string input, int *n_byte) {
    Byte *blocks = (Byte *)input.c_str();
    int length = input.length();

    int bitLength = length * 8;
    int paddingBits = bitLength % 512;
    
    if (paddingBits > 448) {
        paddingBits = 512 - (paddingBits - 448);
    }
    else if (paddingBits < 448) {
        paddingBits = 448 - paddingBits;
    }
    else if (paddingBits == 448) {
        paddingBits = 512;
    }

    int paddingBytes = paddingBits / 8;
    int paddedLength = length + paddingBytes + 8;
    Byte *paddedMessage = new Byte[paddedLength];

    memcpy(paddedMessage, blocks, length);
    paddedMessage[length] = 0x80;
    memset(paddedMessage + length + 1, 0, paddingBytes - 1);

    for (int i = 0; i < 8; ++i) {
        paddedMessage[length + paddingBytes + i] = ((uint64_t)length * 8 >> (i * 8)) & 0xFF;
    }

    *n_byte = paddedLength;
    return paddedMessage;
}

void AVX2_MD5Hash(string input, bit32 *state) {
    Byte* paddedMessages[8];
    int messageLengths[8];
    
    for (int i = 0; i < 8; i++) {
        paddedMessages[i] = StringProcess(std::string(1, input[i]), &messageLengths[i]);
        assert(messageLengths[i] % 64 == 0);
    }
    
    int min_blocks = messageLengths[0] / 64;
    for (int i = 1; i < 8; i++) {
        if (messageLengths[i]/64 < min_blocks) {
            min_blocks = messageLengths[i]/64;
        }
    }
    
    __m256i states_avx[4] = {
        _mm256_set1_epi32(0x67452301),
        _mm256_set1_epi32(0xefcdab89),
        _mm256_set1_epi32(0x98badcfe),
        _mm256_set1_epi32(0x10325476)
    };
    
    for (int block = 0; block < min_blocks; block++) {
        __m256i X[16];
        
        // Load and transpose the 8 messages into 16 __m256i registers
        for (int i = 0; i < 16; i++) {
            uint32_t tmp[8];
            for (int msg = 0; msg < 8; msg++) {
                const Byte* block_start = paddedMessages[msg] + block * 64;
                const Byte* word_ptr = block_start + i*4;
                tmp[msg] = *((uint32_t*)word_ptr);
            }
            X[i] = _mm256_set_epi32(tmp[7], tmp[6], tmp[5], tmp[4], tmp[3], tmp[2], tmp[1], tmp[0]);
        }

        __m256i a = states_avx[0];
        __m256i b = states_avx[1];
        __m256i c = states_avx[2];
        __m256i d = states_avx[3];

        /* Round 1 */
        AVX2_FF(a, b, c, d, X[0], s11, 0xd76aa478);
        AVX2_FF(d, a, b, c, X[1], s12, 0xe8c7b756);
        AVX2_FF(c, d, a, b, X[2], s13, 0x242070db);
        AVX2_FF(b, c, d, a, X[3], s14, 0xc1bdceee);
        AVX2_FF(a, b, c, d, X[4], s11, 0xf57c0faf);
        AVX2_FF(d, a, b, c, X[5], s12, 0x4787c62a);
        AVX2_FF(c, d, a, b, X[6], s13, 0xa8304613);
        AVX2_FF(b, c, d, a, X[7], s14, 0xfd469501);
        AVX2_FF(a, b, c, d, X[8], s11, 0x698098d8);
        AVX2_FF(d, a, b, c, X[9], s12, 0x8b44f7af);
        AVX2_FF(c, d, a, b, X[10], s13, 0xffff5bb1);
        AVX2_FF(b, c, d, a, X[11], s14, 0x895cd7be);
        AVX2_FF(a, b, c, d, X[12], s11, 0x6b901122);
        AVX2_FF(d, a, b, c, X[13], s12, 0xfd987193);
        AVX2_FF(c, d, a, b, X[14], s13, 0xa679438e);
        AVX2_FF(b, c, d, a, X[15], s14, 0x49b40821);

        /* Round 2 */
        AVX2_GG(a, b, c, d, X[1], s21, 0xf61e2562);
        AVX2_GG(d, a, b, c, X[6], s22, 0xc040b340);
        AVX2_GG(c, d, a, b, X[11], s23, 0x265e5a51);
        AVX2_GG(b, c, d, a, X[0], s24, 0xe9b6c7aa);
        AVX2_GG(a, b, c, d, X[5], s21, 0xd62f105d);
        AVX2_GG(d, a, b, c, X[10], s22, 0x2441453);
        AVX2_GG(c, d, a, b, X[15], s23, 0xd8a1e681);
        AVX2_GG(b, c, d, a, X[4], s24, 0xe7d3fbc8);
        AVX2_GG(a, b, c, d, X[9], s21, 0x21e1cde6);
        AVX2_GG(d, a, b, c, X[14], s22, 0xc33707d6);
        AVX2_GG(c, d, a, b, X[3], s23, 0xf4d50d87);
        AVX2_GG(b, c, d, a, X[8], s24, 0x455a14ed);
        AVX2_GG(a, b, c, d, X[13], s21, 0xa9e3e905);
        AVX2_GG(d, a, b, c, X[2], s22, 0xfcefa3f8);
        AVX2_GG(c, d, a, b, X[7], s23, 0x676f02d9);
        AVX2_GG(b, c, d, a, X[12], s24, 0x8d2a4c8a);

        /* Round 3 */
        AVX2_HH(a, b, c, d, X[5], s31, 0xfffa3942);
        AVX2_HH(d, a, b, c, X[8], s32, 0x8771f681);
        AVX2_HH(c, d, a, b, X[11], s33, 0x6d9d6122);
        AVX2_HH(b, c, d, a, X[14], s34, 0xfde5380c);
        AVX2_HH(a, b, c, d, X[1], s31, 0xa4beea44);
        AVX2_HH(d, a, b, c, X[4], s32, 0x4bdecfa9);
        AVX2_HH(c, d, a, b, X[7], s33, 0xf6bb4b60);
        AVX2_HH(b, c, d, a, X[10], s34, 0xbebfbc70);
        AVX2_HH(a, b, c, d, X[13], s31, 0x289b7ec6);
        AVX2_HH(d, a, b, c, X[0], s32, 0xeaa127fa);
        AVX2_HH(c, d, a, b, X[3], s33, 0xd4ef3085);
        AVX2_HH(b, c, d, a, X[6], s34, 0x4881d05);
        AVX2_HH(a, b, c, d, X[9], s31, 0xd9d4d039);
        AVX2_HH(d, a, b, c, X[12], s32, 0xe6db99e5);
        AVX2_HH(c, d, a, b, X[15], s33, 0x1fa27cf8);
        AVX2_HH(b, c, d, a, X[2], s34, 0xc4ac5665);

        /* Round 4 */
        AVX2_II(a, b, c, d, X[0], s41, 0xf4292244);
        AVX2_II(d, a, b, c, X[7], s42, 0x432aff97);
        AVX2_II(c, d, a, b, X[14], s43, 0xab9423a7);
        AVX2_II(b, c, d, a, X[5], s44, 0xfc93a039);
        AVX2_II(a, b, c, d, X[12], s41, 0x655b59c3);
        AVX2_II(d, a, b, c, X[3], s42, 0x8f0ccc92);
        AVX2_II(c, d, a, b, X[10], s43, 0xffeff47d);
        AVX2_II(b, c, d, a, X[1], s44, 0x85845dd1);
        AVX2_II(a, b, c, d, X[8], s41, 0x6fa87e4f);
        AVX2_II(d, a, b, c, X[15], s42, 0xfe2ce6e0);
        AVX2_II(c, d, a, b, X[6], s43, 0xa3014314);
        AVX2_II(b, c, d, a, X[13], s44, 0x4e0811a1);
        AVX2_II(a, b, c, d, X[4], s41, 0xf7537e82);
        AVX2_II(d, a, b, c, X[11], s42, 0xbd3af235);
        AVX2_II(c, d, a, b, X[2], s43, 0x2ad7d2bb);
        AVX2_II(b, c, d, a, X[9], s44, 0xeb86d391);

        states_avx[0] = _mm256_add_epi32(states_avx[0], a);
        states_avx[1] = _mm256_add_epi32(states_avx[1], b);
        states_avx[2] = _mm256_add_epi32(states_avx[2], c);
        states_avx[3] = _mm256_add_epi32(states_avx[3], d);
    }

    // Extract results
    alignas(32) uint32_t state0[8], state1[8], state2[8], state3[8];
    _mm256_store_si256((__m256i*)state0, states_avx[0]);
    _mm256_store_si256((__m256i*)state1, states_avx[1]);
    _mm256_store_si256((__m256i*)state2, states_avx[2]);
    _mm256_store_si256((__m256i*)state3, states_avx[3]);

    for (int i = 0; i < 8; i++) {
        state[i*4] = __builtin_bswap32(state0[i]);
        state[i*4+1] = __builtin_bswap32(state1[i]);
        state[i*4+2] = __builtin_bswap32(state2[i]);
        state[i*4+3] = __builtin_bswap32(state3[i]);
    }
     
    for (int i = 0; i < 8; i++) {
        delete[] paddedMessages[i];
    }
}