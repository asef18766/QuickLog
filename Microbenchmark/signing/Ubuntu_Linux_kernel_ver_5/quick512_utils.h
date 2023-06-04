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

#define AES_ECB_8_(cipher_blks, sched, sign_keys)  \
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
		__m512i dkey = _mm512_broadcast_i32x4(sched[10]);		     	   \
		*((__m512i*)cipher_blks)     = _mm512_aesenclast_epi128 (*((__m512i*)cipher_blks)    , dkey);   \
		*(((__m512i*)cipher_blks)+1) = _mm512_aesenclast_epi128 (*(((__m512i*)cipher_blks)+1), dkey);   \
	}while (0)