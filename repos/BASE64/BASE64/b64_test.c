#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "b64.h"

/*

* str : ���� ������ ����

* enc : base64�� encode�� ���� ������ ����

* dec : base64�� decode�� ���� ������ ����

*/
int main(void) {

	// �� "AB"�� str�� ����

	unsigned char *str = "AB";


	// base64 encode
	
	char *enc = b64_encode(str, strlen(str));

	printf("%s\n", enc); // base64�� encode�� ���� QUI=�� ���


	// base64 decode
	
	char *dec = b64_decode(enc, strlen(enc));

	printf("%s\n", dec); // base64�� decode�� ���� AB�� ���
	
	// allocation_free

	free(enc);
	free(dec);
	return 0;
}