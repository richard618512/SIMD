#include "md5_neon.h"
#include <iomanip>
#include <assert.h>
#include <chrono>
#include <arm_neon.h>

using namespace std;
using namespace chrono;


/**
 * StringProcess: 将单个输入字符串转换成MD5计算所需的消息数组
 * @param input 输入
 * @param[out] n_byte 用于给调用者传递额外的返回值，即最终Byte数组的长度
 * @return Byte消息数组
 */
Byte *StringProcess(string input, int *n_byte)
{
	// 将输入的字符串转换为Byte为单位的数组
	Byte *blocks = (Byte *)input.c_str();
	int length = input.length();

	// 计算原始消息长度（以比特为单位）
	int bitLength = length * 8;

	// paddingBits: 原始消息需要的padding长度（以bit为单位）
	// 对于给定的消息，将其补齐至length%512==448为止
	// 需要注意的是，即便给定的消息满足length%512==448，也需要再pad 512bits
	int paddingBits = bitLength % 512;
	if (paddingBits > 448)
	{
		paddingBits = 512 - (paddingBits - 448);
	}
	else if (paddingBits < 448)
	{
		paddingBits = 448 - paddingBits;
	}
	else if (paddingBits == 448)
	{
		paddingBits = 512;
	}

	// 原始消息需要的padding长度（以Byte为单位）
	int paddingBytes = paddingBits / 8;
	// 创建最终的字节数组
	// length + paddingBytes + 8:
	// 1. length为原始消息的长度（bits）
	// 2. paddingBytes为原始消息需要的padding长度（Bytes）
	// 3. 在pad到length%512==448之后，需要额外附加64bits的原始消息长度，即8个bytes
	int paddedLength = length + paddingBytes + 8;
	Byte *paddedMessage = new Byte[paddedLength];

	// 复制原始消息
	memcpy(paddedMessage, blocks, length);

	// 添加填充字节。填充时，第一位为1，后面的所有位均为0。
	// 所以第一个byte是0x80
	paddedMessage[length] = 0x80;							 // 添加一个0x80字节
	memset(paddedMessage + length + 1, 0, paddingBytes - 1); // 填充0字节

	// 添加消息长度（64比特，小端格式）
	for (int i = 0; i < 8; ++i)
	{
		// 特别注意此处应当将bitLength转换为uint64_t
		// 这里的length是原始消息的长度
		paddedMessage[length + paddingBytes + i] = ((uint64_t)length * 8 >> (i * 8)) & 0xFF;
	}

	// 验证长度是否满足要求。此时长度应当是512bit的倍数
	int residual = 8 * paddedLength % 512;
	// assert(residual == 0);

	// 在填充+添加长度之后，消息被分为n_blocks个512bit的部分
	*n_byte = paddedLength;
	return paddedMessage;
}


/**
 * MD5Hash: 将单个输入字符串转换成MD5
 * @param input 输入
 * @param[out] state 用于给调用者传递额外的返回值，即最终的缓冲区，也就是MD5的结果
 * @return Byte消息数组
 */
void NEON_MD5Hash(string input, bit32 *state)
{
    //本人将对代码的一些理解写到了注释里，绝对都是本人自己的思考，就是可能有点啰嗦见谅......
    Byte* paddedMessages[4];
    int messageLengths[4];
    
    // 1. 并行预处理4个输入
    for (int i = 0; i < 4; i++) {
        paddedMessages[i] = StringProcess(std::string(1, input[i]), &messageLengths[i]);
        assert(messageLengths[i] % 64 == 0);//断言检查，确定消息长度一定是64字节的倍数（512bit）
		//在这里对源代码进行了修改，因为不太清楚为什么要写成assert(messageLength[i] == messageLength[0])的形式，
		//感觉这样没有实现将消息长度限制在512bit的切片
    }
    
    // 2. 确定最小块数（以最短消息为准）
    int min_blocks = messageLengths[0] / 64;
    for (int i = 1; i < 4; i++) {
        if (messageLengths[i]/64 < min_blocks) {
            min_blocks = messageLengths[i]/64;
        }//类似于找数组最小值，串行代码只有一个message length所以没有这一步；
    }
    
    // 3. 初始化4个并行状态向量
    uint32x4_t states_neon[4] = {
        {0x67452301, 0x67452301, 0x67452301, 0x67452301},
        {0xefcdab89, 0xefcdab89, 0xefcdab89, 0xefcdab89},
        {0x98badcfe, 0x98badcfe, 0x98badcfe, 0x98badcfe},
        {0x10325476, 0x10325476, 0x10325476, 0x10325476}
    };//四个相同的副本使得能够同时对四条口令进行处理，这个和串行代码区别不大，就是从一个扩充到四个能进行并行处理了
    
    // 4. 并行处理块
	//先解释一下串行代码：for (int i1 = 0; i1 < 16; ++i1)
		// {
		// 	x[i1] = (paddedMessage[4 * i1 + i * 64]) |
		// 			(paddedMessage[4 * i1 + 1 + i * 64] << 8) |
		// 			(paddedMessage[4 * i1 + 2 + i * 64] << 16) |
		// 			(paddedMessage[4 * i1 + 3 + i * 64] << 24);
		// }这一块就是手动将信息中的4个字节拼成了一个32位字
		//bit32 a = state[0], b = state[1], c = state[2], d = state[3]; 这个地方就是用四个变量存储最初的哈希值，由于state[i]都是单一值，所以注定了一次只能处理一条信息
    for (int block = 0; block < min_blocks; block++) {
        uint32x4_t X[16][4];// X[i][j]表示第j个信息的第i个32位字
        
        for (int msg = 0; msg < 4; msg++) {
            const Byte* block_start = paddedMessages[msg] + block * 64;// X[i][j]表示第j个信息的第i个32位字
            for (int i = 0; i < 16; i++) {
                const Byte* word_ptr = block_start + i*4;//计算块中第i个字的地址
                X[i][msg] = vld1q_u32((const uint32_t*)word_ptr);//一次从对应地址中取出四个字节拼成32位字
            }
        }
         // 转置：将数据转置为[message][round]→[round][message]
		//原来的存储是按照信息来存的，现在改为按字来存，即每一个x[i]都是并行处理的四条信息的第i个字，因为我们并行的思路是要一次对多个信息进行处理，原来的按信息来存储使得我们很难并行的对不同信息的同一位置的字进行处理
		//因为这样只能串行的从每个数组中去读取，浪费性能，因此这一步转置我认为是提升性能较为关键的一步
        uint32x4_t x[16];
        for (int i = 0; i < 16; i++) {
            uint32_t tmp[4];
            for (int msg = 0; msg < 4; msg++) {
                tmp[msg] = vgetq_lane_u32(X[i][msg], 0);
            }
            x[i] = vld1q_u32(tmp);
        }
        //x[i]存储的就是四个消息的第i个字的拼接
        // 初始化a,b,c,d为4个并行状态
        uint32x4_t a = states_neon[0];
        uint32x4_t b = states_neon[1];
        uint32x4_t c = states_neon[2];
        uint32x4_t d = states_neon[3];

        //下面的四轮处理我并没有进行simd并行处理，因为每一条运算之间是存在依赖关系的，好像不太能并行计算，所以只是对四种运算进行了并行处理

        /* Round 1 */
        NEON_FF(a, b, c, d, x[0], s11, 0xd76aa478);
        NEON_FF(d, a, b, c, x[1], s12, 0xe8c7b756);
        NEON_FF(c, d, a, b, x[2], s13, 0x242070db);
        NEON_FF(b, c, d, a, x[3], s14, 0xc1bdceee);
        NEON_FF(a, b, c, d, x[4], s11, 0xf57c0faf);
        NEON_FF(d, a, b, c, x[5], s12, 0x4787c62a);
        NEON_FF(c, d, a, b, x[6], s13, 0xa8304613);
        NEON_FF(b, c, d, a, x[7], s14, 0xfd469501);
        NEON_FF(a, b, c, d, x[8], s11, 0x698098d8);
        NEON_FF(d, a, b, c, x[9], s12, 0x8b44f7af);
        NEON_FF(c, d, a, b, x[10], s13, 0xffff5bb1);
        NEON_FF(b, c, d, a, x[11], s14, 0x895cd7be);
        NEON_FF(a, b, c, d, x[12], s11, 0x6b901122);
        NEON_FF(d, a, b, c, x[13], s12, 0xfd987193);
        NEON_FF(c, d, a, b, x[14], s13, 0xa679438e);
        NEON_FF(b, c, d, a, x[15], s14, 0x49b40821);

        /* Round 2 */
        NEON_GG(a, b, c, d, x[1], s21, 0xf61e2562);
        NEON_GG(d, a, b, c, x[6], s22, 0xc040b340);
        NEON_GG(c, d, a, b, x[11], s23, 0x265e5a51);
        NEON_GG(b, c, d, a, x[0], s24, 0xe9b6c7aa);
        NEON_GG(a, b, c, d, x[5], s21, 0xd62f105d);
        NEON_GG(d, a, b, c, x[10], s22, 0x2441453);
        NEON_GG(c, d, a, b, x[15], s23, 0xd8a1e681);
        NEON_GG(b, c, d, a, x[4], s24, 0xe7d3fbc8);
        NEON_GG(a, b, c, d, x[9], s21, 0x21e1cde6);
        NEON_GG(d, a, b, c, x[14], s22, 0xc33707d6);
        NEON_GG(c, d, a, b, x[3], s23, 0xf4d50d87);
        NEON_GG(b, c, d, a, x[8], s24, 0x455a14ed);
        NEON_GG(a, b, c, d, x[13], s21, 0xa9e3e905);
        NEON_GG(d, a, b, c, x[2], s22, 0xfcefa3f8);
        NEON_GG(c, d, a, b, x[7], s23, 0x676f02d9);
        NEON_GG(b, c, d, a, x[12], s24, 0x8d2a4c8a);

        /* Round 3 */
        NEON_HH(a, b, c, d, x[5], s31, 0xfffa3942);
        NEON_HH(d, a, b, c, x[8], s32, 0x8771f681);
        NEON_HH(c, d, a, b, x[11], s33, 0x6d9d6122);
        NEON_HH(b, c, d, a, x[14], s34, 0xfde5380c);
        NEON_HH(a, b, c, d, x[1], s31, 0xa4beea44);
        NEON_HH(d, a, b, c, x[4], s32, 0x4bdecfa9);
        NEON_HH(c, d, a, b, x[7], s33, 0xf6bb4b60);
        NEON_HH(b, c, d, a, x[10], s34, 0xbebfbc70);
        NEON_HH(a, b, c, d, x[13], s31, 0x289b7ec6);
        NEON_HH(d, a, b, c, x[0], s32, 0xeaa127fa);
        NEON_HH(c, d, a, b, x[3], s33, 0xd4ef3085);
        NEON_HH(b, c, d, a, x[6], s34, 0x4881d05);
        NEON_HH(a, b, c, d, x[9], s31, 0xd9d4d039);
        NEON_HH(d, a, b, c, x[12], s32, 0xe6db99e5);
        NEON_HH(c, d, a, b, x[15], s33, 0x1fa27cf8);
        NEON_HH(b, c, d, a, x[2], s34, 0xc4ac5665);

        /* Round 4 */
        NEON_II(a, b, c, d, x[0], s41, 0xf4292244);
        NEON_II(d, a, b, c, x[7], s42, 0x432aff97);
        NEON_II(c, d, a, b, x[14], s43, 0xab9423a7);
        NEON_II(b, c, d, a, x[5], s44, 0xfc93a039);
        NEON_II(a, b, c, d, x[12], s41, 0x655b59c3);
        NEON_II(d, a, b, c, x[3], s42, 0x8f0ccc92);
        NEON_II(c, d, a, b, x[10], s43, 0xffeff47d);
        NEON_II(b, c, d, a, x[1], s44, 0x85845dd1);
        NEON_II(a, b, c, d, x[8], s41, 0x6fa87e4f);
        NEON_II(d, a, b, c, x[15], s42, 0xfe2ce6e0);
        NEON_II(c, d, a, b, x[6], s43, 0xa3014314);
        NEON_II(b, c, d, a, x[13], s44, 0x4e0811a1);
        NEON_II(a, b, c, d, x[4], s41, 0xf7537e82);
        NEON_II(d, a, b, c, x[11], s42, 0xbd3af235);
        NEON_II(c, d, a, b, x[2], s43, 0x2ad7d2bb);
        NEON_II(b, c, d, a, x[9], s44, 0xeb86d391);

        // --- 最后累加到原状态 ---
        states_neon[0] = vaddq_u32(states_neon[0], a);
        states_neon[1] = vaddq_u32(states_neon[1], b);
        states_neon[2] = vaddq_u32(states_neon[2], c);
        states_neon[3] = vaddq_u32(states_neon[3], d);
    }
    // 存储结果并处理字节序
	 //因为我们在之前将信息拆成了按字存储便于运算，但由于最终的输出结果还是要按照信息来排序，因此这里就是重新将按字存储的状态值还原为按信息存储的状态值，便于我们进行最终的输出
	 for (int msg = 0; msg < 4; msg++) {
		uint32_t state[4];
		// 提取并转换 state 的字节序
		state[0] = __builtin_bswap32(vgetq_lane_u32(states_neon[0], 0));
        state[1] = __builtin_bswap32(vgetq_lane_u32(states_neon[1], 1));
        state[2] = __builtin_bswap32(vgetq_lane_u32(states_neon[2], 2));
        state[3] = __builtin_bswap32(vgetq_lane_u32(states_neon[3], 3));
		
		// 存储到最终输出
		memcpy(&state[msg], state, sizeof(state));
	}
	 
	 // 释放内存
	 for (int i = 0; i < 4; i++) {
		 delete[] paddedMessages[i];
	 }
	 //在我看来，整个并行算法相较于串行算法最主要得到优化的地方就是在真正进行运算之前，在四轮运算之前，我们将单独处理一条信息转变为处理四条信息，再将四条信息的存储方式进行改变，将信息以字为单位进行打散，将四个信息的相同位置的字进行重组存储，从而能够真正的实现并行计算
	 
}


