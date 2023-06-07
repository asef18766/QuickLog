#pragma once
#define  _MM_MALLOC_H_INCLUDED
#include <x86intrin.h>
#undef _MM_MALLOC_H_INCLUDED


#define prernd_8_(cipher_blks, key)                       \
	do{                                                  \
		cipher_blks[0] = _mm_xor_si128(cipher_blks[0], key); \
		cipher_blks[1] = _mm_xor_si128(cipher_blks[1], key); \
		cipher_blks[2] = _mm_xor_si128(cipher_blks[2], key); \
		cipher_blks[3] = _mm_xor_si128(cipher_blks[3], key); \
		cipher_blks[4] = _mm_xor_si128(cipher_blks[4], key); \
		cipher_blks[5] = _mm_xor_si128(cipher_blks[5], key); \
		cipher_blks[6] = _mm_xor_si128(cipher_blks[6], key); \
		cipher_blks[7] = _mm_xor_si128(cipher_blks[7], key); \
	} while(0)

#define prernd_4_(cipher_blks, key)                       \
	do{                                                  \
		cipher_blks[0] = _mm_xor_si128(cipher_blks[0], sign_keys); \
		cipher_blks[1] = _mm_xor_si128(cipher_blks[1], sign_keys); \
		cipher_blks[2] = _mm_xor_si128(cipher_blks[2], sign_keys); \
		cipher_blks[3] = _mm_xor_si128(cipher_blks[3], sign_keys); \
	} while(0)

#define tag_8_xor_(tag_blks,cipher_blks)  \
  do{  \
	__m512i tag_ = _mm512_xor_epi64(*((__m512i*)cipher_blks), *(((__m512i*)cipher_blks)+1)); \
	__m256i tag__  = _mm256_xor_si256(*((__m256i*)&tag_), *(((__m256i*)&tag_)+1)); \
	tag_blks[2] =_mm_xor_si128(tag_blks[2], _mm_xor_si128(*((__m128i*)&tag__), *(((__m128i*)&tag__)+1))); \
  } while(0)

#define enc_8_(cipher_blks, key)                                   \
	do{                                                            \
		__m512i dkey = _mm512_broadcast_i32x4(key);		     	   \
		*((__m512i*)cipher_blks)     = _mm512_aesenc_epi128(*((__m512i*)cipher_blks)    , dkey);   \
		*(((__m512i*)cipher_blks)+1) = _mm512_aesenc_epi128(*(((__m512i*)cipher_blks)+1), dkey);   \
  	}while(0)

#define enc_4_(cipher_blks, key)                                 \
	do{                                                         \
		*((__m512i*)cipher_blks)     = _mm512_aesenc_epi128(*((__m512i*)cipher_blks)    , _mm512_broadcast_i32x4(key));  \
	}while(0)

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
		*((__m512i*)cipher_blks)     = _mm512_aesenclast_epi128 (*((__m512i*)cipher_blks)    , _mm512_broadcast_i32x4(sched[10]));  \
	}while (0)

#define tag_8_xor_(tag_blks,cipher_blks)  \
  do{  \
	__m512i tag_ = _mm512_xor_epi64(*((__m512i*)cipher_blks), *(((__m512i*)cipher_blks)+1)); \
	__m256i tag__  = _mm256_xor_si256(*((__m256i*)&tag_), *(((__m256i*)&tag_)+1)); \
	tag_blks[2] =_mm_xor_si128(tag_blks[2], _mm_xor_si128(*((__m128i*)&tag__), *(((__m128i*)&tag__)+1))); \
  } while(0)