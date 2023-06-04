#define  _MM_MALLOC_H_INCLUDED
#include <x86intrin.h>
#undef _MM_MALLOC_H_INCLUDED
#define xor_block(x,y)        _mm_xor_si128(x,y)

#define prernd_8(cipher_blks, key)                       \
	do{                                                  \
		cipher_blks[0] = xor_block(cipher_blks[0], key); \
		cipher_blks[1] = xor_block(cipher_blks[1], key); \
		cipher_blks[2] = xor_block(cipher_blks[2], key); \
		cipher_blks[3] = xor_block(cipher_blks[3], key); \
		cipher_blks[4] = xor_block(cipher_blks[4], key); \
		cipher_blks[5] = xor_block(cipher_blks[5], key); \
		cipher_blks[6] = xor_block(cipher_blks[6], key); \
		cipher_blks[7] = xor_block(cipher_blks[7], key); \
	} while(0)
#define enc_8(cipher_blks, key)                                 \
	do{                                                         \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], key); \
		cipher_blks[1] = _mm_aesenc_si128(cipher_blks[1], key); \
		cipher_blks[2] = _mm_aesenc_si128(cipher_blks[2], key); \
		cipher_blks[3] = _mm_aesenc_si128(cipher_blks[3], key); \
		cipher_blks[4] = _mm_aesenc_si128(cipher_blks[4], key); \
		cipher_blks[5] = _mm_aesenc_si128(cipher_blks[5], key); \
		cipher_blks[6] = _mm_aesenc_si128(cipher_blks[6], key); \
		cipher_blks[7] = _mm_aesenc_si128(cipher_blks[7], key); \
  	}while(0)
#define AES_ECB_8(cipher_blks, sched, sign_keys)   \
	do{                                        	   \
		prernd_8(cipher_blks,sign_keys);           \
		enc_8(cipher_blks, sched[1]);              \
		enc_8(cipher_blks, sched[2]);              \
		enc_8(cipher_blks, sched[3]);              \
		enc_8(cipher_blks, sched[4]);              \
		enc_8(cipher_blks, sched[5]);              \
		enc_8(cipher_blks, sched[6]);              \
		enc_8(cipher_blks, sched[7]);              \
		enc_8(cipher_blks, sched[8]);              \
		enc_8(cipher_blks, sched[9]);              \
		cipher_blks[0] =_mm_aesenclast_si128(cipher_blks[0], sched[10]); \
		cipher_blks[1] =_mm_aesenclast_si128(cipher_blks[1], sched[10]); \
		cipher_blks[2] =_mm_aesenclast_si128(cipher_blks[2], sched[10]); \
		cipher_blks[3] =_mm_aesenclast_si128(cipher_blks[3], sched[10]); \
		cipher_blks[4] =_mm_aesenclast_si128(cipher_blks[4], sched[10]); \
		cipher_blks[5] =_mm_aesenclast_si128(cipher_blks[5], sched[10]); \
		cipher_blks[6] =_mm_aesenclast_si128(cipher_blks[6], sched[10]); \
		cipher_blks[7] =_mm_aesenclast_si128(cipher_blks[7], sched[10]); \
	}while (0)


typedef __m128i block;
#include <stdlib.h>
#include  <stdio.h>
#include <stdint.h>
void fill_random(uint8_t* ptr, int cnt)
{
    for (int i = 0; i != cnt;  ++i)
    {
        uint8_t rd = (rand() % 256);
        ptr[i] = rd;
        //printf("got %x\n", rd);
    }
}
void printhex(uint8_t* ptr, int cnt)
{
    for (int i = 0; i != cnt; ++i)
	{
		printf("%02x", ptr[i]);
		if (i % 8 == 7)
			puts("");
	}
}
#include "quick512_utils.h"
int main()
{
	
	srand(48763);
    block cipher_blks[8];
    block sched[11];
    block mask;

    fill_random((uint8_t*)cipher_blks, sizeof(cipher_blks));
    puts("cipher_blks:");
    printhex((uint8_t*)cipher_blks, sizeof(cipher_blks));
    puts("");

	fill_random((uint8_t*)&mask, sizeof(mask));
    puts("mask:");
    printhex((uint8_t*)&mask, sizeof(mask));
    puts("");

    fill_random((uint8_t*)sched, sizeof(sched));
    puts("sched:");
    printhex((uint8_t*)sched, sizeof(sched));
    puts("");

	AES_ECB_8(cipher_blks, sched, mask);
	puts("res:");
    printhex((uint8_t*)cipher_blks, sizeof(cipher_blks));
    puts("");

	puts("============================");
	srand(48763);
    fill_random((uint8_t*)cipher_blks, sizeof(cipher_blks));
    puts("cipher_blks:");
    printhex((uint8_t*)cipher_blks, sizeof(cipher_blks));
    puts("");

	fill_random((uint8_t*)&mask, sizeof(mask));
    puts("mask:");
    printhex((uint8_t*)&mask, sizeof(mask));
    puts("");

    fill_random((uint8_t*)sched, sizeof(sched));
    puts("sched:");
    printhex((uint8_t*)sched, sizeof(sched));
    puts("");

	AES_ECB_8_(cipher_blks, sched, mask);
	puts("res:");
    printhex((uint8_t*)cipher_blks, sizeof(cipher_blks));
    puts("");

}