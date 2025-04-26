// md5_sse.cpp
#include "md5_sse.h"
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

void SSE_MD5Hash(string input, bit32 *state) {
    Byte* paddedMessages[4];
    int messageLengths[4];
    
    for (int i = 0; i < 4; i++) {
        paddedMessages[i] = StringProcess(std::string(1, input[i]), &messageLengths[i]);
        assert(messageLengths[i] % 64 == 0);
    }
    
    int min_blocks = messageLengths[0] / 64;
    for (int i = 1; i < 4; i++) {
        if (messageLengths[i]/64 < min_blocks) {
            min_blocks = messageLengths[i]/64;
        }
    }
    
    __m128i states_sse[4] = {
        _mm_set1_epi32(0x67452301),
        _mm_set1_epi32(0xefcdab89),
        _mm_set1_epi32(0x98badcfe),
        _mm_set1_epi32(0x10325476)
    };
    
    for (int block = 0; block < min_blocks; block++) {
        __m128i X[16];
        
        // Load and transpose the 4 messages into 16 __m128i registers
        for (int i = 0; i < 16; i++) {
            uint32_t tmp[4];
            for (int msg = 0; msg < 4; msg++) {
                const Byte* block_start = paddedMessages[msg] + block * 64;
                const Byte* word_ptr = block_start + i*4;
                tmp[msg] = *((uint32_t*)word_ptr);
            }
            X[i] = _mm_set_epi32(tmp[3], tmp[2], tmp[1], tmp[0]);
        }

        __m128i a = states_sse[0];
        __m128i b = states_sse[1];
        __m128i c = states_sse[2];
        __m128i d = states_sse[3];

        /* Round 1 */
        SSE_FF(a, b, c, d, X[0], s11, 0xd76aa478);
        SSE_FF(d, a, b, c, X[1], s12, 0xe8c7b756);
        SSE_FF(c, d, a, b, X[2], s13, 0x242070db);
        SSE_FF(b, c, d, a, X[3], s14, 0xc1bdceee);
        SSE_FF(a, b, c, d, X[4], s11, 0xf57c0faf);
        SSE_FF(d, a, b, c, X[5], s12, 0x4787c62a);
        SSE_FF(c, d, a, b, X[6], s13, 0xa8304613);
        SSE_FF(b, c, d, a, X[7], s14, 0xfd469501);
        SSE_FF(a, b, c, d, X[8], s11, 0x698098d8);
        SSE_FF(d, a, b, c, X[9], s12, 0x8b44f7af);
        SSE_FF(c, d, a, b, X[10], s13, 0xffff5bb1);
        SSE_FF(b, c, d, a, X[11], s14, 0x895cd7be);
        SSE_FF(a, b, c, d, X[12], s11, 0x6b901122);
        SSE_FF(d, a, b, c, X[13], s12, 0xfd987193);
        SSE_FF(c, d, a, b, X[14], s13, 0xa679438e);
        SSE_FF(b, c, d, a, X[15], s14, 0x49b40821);

        /* Round 2 */
        SSE_GG(a, b, c, d, X[1], s21, 0xf61e2562);
        SSE_GG(d, a, b, c, X[6], s22, 0xc040b340);
        SSE_GG(c, d, a, b, X[11], s23, 0x265e5a51);
        SSE_GG(b, c, d, a, X[0], s24, 0xe9b6c7aa);
        SSE_GG(a, b, c, d, X[5], s21, 0xd62f105d);
        SSE_GG(d, a, b, c, X[10], s22, 0x2441453);
        SSE_GG(c, d, a, b, X[15], s23, 0xd8a1e681);
        SSE_GG(b, c, d, a, X[4], s24, 0xe7d3fbc8);
        SSE_GG(a, b, c, d, X[9], s21, 0x21e1cde6);
        SSE_GG(d, a, b, c, X[14], s22, 0xc33707d6);
        SSE_GG(c, d, a, b, X[3], s23, 0xf4d50d87);
        SSE_GG(b, c, d, a, X[8], s24, 0x455a14ed);
        SSE_GG(a, b, c, d, X[13], s21, 0xa9e3e905);
        SSE_GG(d, a, b, c, X[2], s22, 0xfcefa3f8);
        SSE_GG(c, d, a, b, X[7], s23, 0x676f02d9);
        SSE_GG(b, c, d, a, X[12], s24, 0x8d2a4c8a);

        /* Round 3 */
        SSE_HH(a, b, c, d, X[5], s31, 0xfffa3942);
        SSE_HH(d, a, b, c, X[8], s32, 0x8771f681);
        SSE_HH(c, d, a, b, X[11], s33, 0x6d9d6122);
        SSE_HH(b, c, d, a, X[14], s34, 0xfde5380c);
        SSE_HH(a, b, c, d, X[1], s31, 0xa4beea44);
        SSE_HH(d, a, b, c, X[4], s32, 0x4bdecfa9);
        SSE_HH(c, d, a, b, X[7], s33, 0xf6bb4b60);
        SSE_HH(b, c, d, a, X[10], s34, 0xbebfbc70);
        SSE_HH(a, b, c, d, X[13], s31, 0x289b7ec6);
        SSE_HH(d, a, b, c, X[0], s32, 0xeaa127fa);
        SSE_HH(c, d, a, b, X[3], s33, 0xd4ef3085);
        SSE_HH(b, c, d, a, X[6], s34, 0x4881d05);
        SSE_HH(a, b, c, d, X[9], s31, 0xd9d4d039);
        SSE_HH(d, a, b, c, X[12], s32, 0xe6db99e5);
        SSE_HH(c, d, a, b, X[15], s33, 0x1fa27cf8);
        SSE_HH(b, c, d, a, X[2], s34, 0xc4ac5665);

        /* Round 4 */
        SSE_II(a, b, c, d, X[0], s41, 0xf4292244);
        SSE_II(d, a, b, c, X[7], s42, 0x432aff97);
        SSE_II(c, d, a, b, X[14], s43, 0xab9423a7);
        SSE_II(b, c, d, a, X[5], s44, 0xfc93a039);
        SSE_II(a, b, c, d, X[12], s41, 0x655b59c3);
        SSE_II(d, a, b, c, X[3], s42, 0x8f0ccc92);
        SSE_II(c, d, a, b, X[10], s43, 0xffeff47d);
        SSE_II(b, c, d, a, X[1], s44, 0x85845dd1);
        SSE_II(a, b, c, d, X[8], s41, 0