#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "b64.h"

/*

* plaintext : ���� ������ ����

* enc : base64�� encode�� ���� ������ ����

* dec : base64�� decode�� ���� ������ ����

*/
int main(void) {

	// �� "AB"�� plaintext�� ����

	unsigned char *plaintext = "AB";


	// base64 encode
	
	char *enc = b64_encode(plaintext, strlen(plaintext));

	printf("%s\n", enc); // base64�� encode�� ���� QUI=�� ���


	// base64 decode
	size_t dec_size;
	char *dec = b64_decode_ex(enc, strlen(enc), &dec_size);

	printf("%s\n", dec); // base64�� decode�� ���� AB�� ���
	
	// allocation_free

	free(enc);
	free(dec);
	return 0;
}