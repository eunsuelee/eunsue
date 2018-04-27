

#include <stdio.h>

#include <stdlib.h>

#include "b64.h"



#ifdef b64_USE_CUSTOM_MALLOC

extern void* b64_malloc(size_t);

#endif



#ifdef b64_USE_CUSTOM_REALLOC

extern void* b64_realloc(void*, size_t);

#endif



// base64�� encode�ϴ� �Լ�
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



	// source�� ������ parse

	while (len--) {

		// 'tmp'�� �ѹ��� �ִ� 3 byte�� �о����

		tmp[i++] = *(src++);



		// 3 bytes�� �о��ٸ� buf�� encode

		if (3 == i) {

			buf[0] = (tmp[0] & 0xfc) >> 2;

			buf[1] = ((tmp[0] & 0x03) << 4) + ((tmp[1] & 0xf0) >> 4);

			buf[2] = ((tmp[1] & 0x0f) << 2) + ((tmp[2] & 0xc0) >> 6);

			buf[3] = tmp[2] & 0x3f;



			// 'enc'�� ���ο� 4 bytes�� �Ҵ��ϰ�

			// unsigned char arry�� 'enc'�� 

			// �� encoded buffer�� base 64 index table�� translate

			enc = (char *)b64_realloc(enc, size + 4);

			for (i = 0; i < 4; ++i) {

				enc[size++] = b64_table[buf[i]];

			}



			// reset index

			i = 0;

		}

	}



	// ������

	if (i > 0) {


		// �ּ� 3�� 'tmp'�� '\0'���� ä���

		for (j = i; j < 3; ++j) {

			tmp[j] = '\0';

		}



		// ���� �Ȱ��� code�� ����

		buf[0] = (tmp[0] & 0xfc) >> 2;

		buf[1] = ((tmp[0] & 0x03) << 4) + ((tmp[1] & 0xf0) >> 4);

		buf[2] = ((tmp[1] & 0x0f) << 2) + ((tmp[2] & 0xc0) >> 6);

		buf[3] = tmp[2] & 0x3f;



		// ���ο� �Ҵ����� 'enc'�� ���� ������ ���� ���� ���� ����

		for (j = 0; (j < i + 1); ++j) {

			enc = (char *)b64_realloc(enc, size + 1);

			enc[size++] = b64_table[buf[j]];

		}



		// ������ �������� �����ִٸ�

		// 'enc'�� '='�� �߰��ϱ�

		while ((i++ < 3)) {

			enc = (char *)b64_realloc(enc, size + 1);

			enc[size++] = '=';

		}

	}



	// �������� '\0'�� �߰��� ����� ������ �ִ��������� Ȯ���ϰ� �ϱ�

	enc = (char *)b64_realloc(enc, size + 1);

	enc[size] = '\0';



	return enc;

}