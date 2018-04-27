

#include <stdio.h>

#include <stdlib.h>

#include "b64.h"



#ifdef b64_USE_CUSTOM_MALLOC

extern void* b64_malloc(size_t);

#endif



#ifdef b64_USE_CUSTOM_REALLOC

extern void* b64_realloc(void*, size_t);

#endif



// base64로 encode하는 함수
char * b64_encode(const unsigned char *src, size_t len) {

	int i = 0;

	int j = 0;

	char *enc = NULL;

	size_t size = 0;

	unsigned char buf[4];

	unsigned char tmp[3];



	// alloc

	enc = (char *)b64_malloc(1);

	if (NULL == enc) { return NULL; }



	// source의 끝까지 parse

	while (len--) {

		// 'tmp'에 한번에 최대 3 byte씩 읽어오기

		tmp[i++] = *(src++);



		// 3 bytes를 읽었다면 buf에 encode

		if (3 == i) {

			buf[0] = (tmp[0] & 0xfc) >> 2;

			buf[1] = ((tmp[0] & 0x03) << 4) + ((tmp[1] & 0xf0) >> 4);

			buf[2] = ((tmp[1] & 0x0f) << 2) + ((tmp[2] & 0xc0) >> 6);

			buf[3] = tmp[2] & 0x3f;



			// 'enc'에 새로운 4 bytes를 할당하고

			// unsigned char arry인 'enc'에 

			// 각 encoded buffer를 base 64 index table로 translate

			enc = (char *)b64_realloc(enc, size + 4);

			for (i = 0; i < 4; ++i) {

				enc[size++] = b64_table[buf[i]];

			}



			// reset index

			i = 0;

		}

	}



	// 나머지

	if (i > 0) {


		// 최소 3번 'tmp'를 '\0'으로 채우기

		for (j = i; j < 3; ++j) {

			tmp[j] = '\0';

		}



		// 위와 똑같은 code를 행함

		buf[0] = (tmp[0] & 0xfc) >> 2;

		buf[1] = ((tmp[0] & 0x03) << 4) + ((tmp[1] & 0xf0) >> 4);

		buf[2] = ((tmp[1] & 0x0f) << 2) + ((tmp[2] & 0xc0) >> 6);

		buf[3] = tmp[2] & 0x3f;



		// 새로운 할당으로 'enc'에 위와 동일한 값을 쓰는 것을 행함

		for (j = 0; (j < i + 1); ++j) {

			enc = (char *)b64_realloc(enc, size + 1);

			enc[size++] = b64_table[buf[j]];

		}



		// 아직도 나머지가 남아있다면

		// 'enc'에 '='을 추가하기

		while ((i++ < 3)) {

			enc = (char *)b64_realloc(enc, size + 1);

			enc[size++] = '=';

		}

	}



	// 마지막에 '\0'을 추가할 충분한 공간이 있는지에대해 확실하게 하기

	enc = (char *)b64_realloc(enc, size + 1);

	enc[size] = '\0';



	return enc;

}