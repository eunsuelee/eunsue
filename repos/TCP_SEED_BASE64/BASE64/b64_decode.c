
#include <stdio.h>

#include <stdlib.h>

#include <ctype.h>

#include "b64.h"



#ifdef b64_USE_CUSTOM_MALLOC

extern void* b64_malloc(size_t);

#endif



#ifdef b64_USE_CUSTOM_REALLOC

extern void* b64_realloc(void*, size_t);

#endif



//unsigned char *b64_decode(const char *src, size_t len) {
//
//	return b64_decode_ex(src, len, NULL);
//
//}



unsigned char *b64_decode_ex(const char *src, size_t len, size_t *decsize) {

	int i = 0;

	int j = 0;

	int l = 0;

	size_t size = 0;

	unsigned char *dec = NULL;

	unsigned char buf[3];

	unsigned char tmp[4];



	// alloc

	dec = (unsigned char *)b64_malloc(1);

	if (NULL == dec) { return NULL; }



	// source의 끝까지 parse

	while (len--) {

		// char가 '='dlrjsk base64 char이 아닐경우 break

		if ('=' == src[j]) { break; }

		if (!(isalnum(src[j]) || '+' == src[j] || '/' == src[j])) { break; }



		// 한번에 최대 4 bytes를 'tmp'에 읽어오기

		tmp[i++] = src[j++];



		// 4 bytes를 읽었다면 'buf'에 decode

		if (4 == i) {

			// table에서 'tmp'에 있는 값 translate

			for (i = 0; i < 4; ++i) {

				// 'b64_table'에서 traslate할 char 찾기

				for (l = 0; l < 64; ++l) {

					if (tmp[i] == b64_table[l]) {

						tmp[i] = l;

						break;

					}

				}

			}



			// decode

			buf[0] = (tmp[0] << 2) + ((tmp[1] & 0x30) >> 4);

			buf[1] = ((tmp[1] & 0xf) << 4) + ((tmp[2] & 0x3c) >> 2);

			buf[2] = ((tmp[2] & 0x3) << 6) + tmp[3];



			// decoded buffer를 `dec'에 쓰기

			dec = (unsigned char *)b64_realloc(dec, size + 3);

			if (dec != NULL) {

				for (i = 0; i < 3; ++i) {

					dec[size++] = buf[i];

				}

			}
			else {

				return NULL;

			}



			// reset

			i = 0;

		}

	}



	// 나머지

	if (i > 0) {

		// 'tmp'를 '\0'으로 4번까지 채움

		for (j = i; j < 4; ++j) {

			tmp[j] = '\0';

		}



		// 나머지 translate

		for (j = 0; j < 4; ++j) {

			// 'b64_table'에서 traslate할 char 찾기

			for (l = 0; l < 64; ++l) {

				if (tmp[j] == b64_table[l]) {

					tmp[j] = l;

					break;

				}

			}

		}



		// 나머지 decode

		buf[0] = (tmp[0] << 2) + ((tmp[1] & 0x30) >> 4);

		buf[1] = ((tmp[1] & 0xf) << 4) + ((tmp[2] & 0x3c) >> 2);

		buf[2] = ((tmp[2] & 0x3) << 6) + tmp[3];



		// 'dec'에 나머지 decoded buffer 쓰기

		dec = (unsigned char *)b64_realloc(dec, size + (i - 1));

		if (dec != NULL) {

			for (j = 0; (j < i - 1); ++j) {

				dec[size++] = buf[j];

			}

		}
		else {

			return NULL;

		}

	}



	// 마지막에 '\0'을 추가할 충분한 공간이 있는지에대해 확실하게 하기

	dec = (unsigned char *)b64_realloc(dec, size + 1);

	if (dec != NULL) {

		dec[size] = '\0';

	}
	else {

		return NULL;

	}


	// decoded string의 크기를 반환

	
	*decsize = size;


	return dec;

}