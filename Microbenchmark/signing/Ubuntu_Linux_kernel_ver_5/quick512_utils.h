#pragma once
#define  _MM_MALLOC_H_INCLUDED
#include <x86intrin.h>
#undef _MM_MALLOC_H_INCLUDED

#define enc_8_(cipher_blks, key)                                   \
	do{                                                            \
		__m512i dkey = _mm512_broadcast_i32x4(key);		     	   \
		*((__m512i*)cipher_blks)     = _mm512_aesenc_epi128(*((__m512i*)cipher_blks)    , dkey);   \
		*(((__m512i*)cipher_blks)+1) = _mm512_aesenc_epi128(*(((__m512i*)cipher_blks)+1), dkey);   \
  	}while(0)

#define enc_4_(cipher_blks, key)                                 \
	do{                                                         \
		*((__m512i*)cipher_blks)     = _mm512_aesenc_epi128(*((__m512i*)cipher_blks)    , _mm512_broadcast_i32x4(key));   \
  	}while(0)

#define enc_3_(cipher_blks, key)                                 \
	do{                                                         \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], key); \
		cipher_blks[1] = _mm_aesenc_si128(cipher_blks[1], key); \
		cipher_blks[2] = _mm_aesenc_si128(cipher_blks[2], key); \
  	}while(0)

#define enc_2_(cipher_blks, key)                                 \
	do{                                                         \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], key); \
		cipher_blks[1] = _mm_aesenc_si128(cipher_blks[1], key); \
  	}while(0)

#define prernd_8_(cipher_blks, key)                       \
	do{                                                  \
		__m512i dkey = _mm512_broadcast_i32x4(key);	     \
		*((__m512i*)cipher_blks)     = _mm512_xor_si512(*((__m512i*)cipher_blks)    , dkey);   \
		*(((__m512i*)cipher_blks)+1) = _mm512_xor_si512(*(((__m512i*)cipher_blks)+1), dkey);   \
	} while(0)

#define prernd_4_(cipher_blks, key)                       \
	do{                                                  \
		*((__m512i*)cipher_blks)     = _mm512_xor_si512(*((__m512i*)cipher_blks)    , _mm512_broadcast_i32x4(key));   \
	} while(0)

#define AES_ECB_8_(cipher_blks, sched, sign_keys)  \
	do{                                        	   \
		prernd_8_(cipher_blks,sign_keys);           \
		enc_8_(cipher_blks, sched[1]);              \
		enc_8_(cipher_blks, sched[2]);              \
		enc_8_(cipher_blks, sched[3]);              \
		enc_8_(cipher_blks, sched[4]);              \
		enc_8_(cipher_blks, sched[5]);              \
		enc_8_(cipher_blks, sched[6]);              \
		enc_8_(cipher_blks, sched[7]);              \
		enc_8_(cipher_blks, sched[8]);              \
		enc_8_(cipher_blks, sched[9]);              \
		__m512i dkey = _mm512_broadcast_i32x4(sched[10]);		     	   \
		*((__m512i*)cipher_blks)     = _mm512_aesenclast_epi128 (*((__m512i*)cipher_blks)    , dkey);   \
		*(((__m512i*)cipher_blks)+1) = _mm512_aesenclast_epi128 (*(((__m512i*)cipher_blks)+1), dkey);   \
	}while (0)

#define AES_ECB_4_(cipher_blks, sched, sign_keys)   \
	do{                                        	   \
		prernd_4_(cipher_blks,sign_keys);           \
		enc_4_(cipher_blks, sched[1]);              \
		enc_4_(cipher_blks, sched[2]);              \
		enc_4_(cipher_blks, sched[3]);              \
		enc_4_(cipher_blks, sched[4]);              \
		enc_4_(cipher_blks, sched[5]);              \
		enc_4_(cipher_blks, sched[6]);              \
		enc_4_(cipher_blks, sched[7]);              \
		enc_4_(cipher_blks, sched[8]);              \
		enc_4_(cipher_blks, sched[9]);              \
		*((__m512i*)cipher_blks)     = _mm512_aesenclast_epi128 (*((__m512i*)cipher_blks)    , _mm512_broadcast_i32x4(sched[10]));   \
	}while (0)