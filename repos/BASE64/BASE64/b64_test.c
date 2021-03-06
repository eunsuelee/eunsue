#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "b64.h"

/*

* plaintext : 평문을 저장할 변수

* enc : base64로 encode한 값을 저장할 변수

* dec : base64로 decode한 값을 저장할 변수

*/
int main(void) {

	// 평문 "AB"를 plaintext에 저장

	unsigned char *plaintext = "AB";


	// base64 encode
	
	char *enc = b64_encode(plaintext, strlen(plaintext));

	printf("%s\n", enc); // base64로 encode된 값인 QUI=가 출력


	// base64 decode
	size_t dec_size;
	char *dec = b64_decode_ex(enc, strlen(enc), &dec_size);

	printf("%s\n", dec); // base64로 decode된 값인 AB가 출력
	
	// allocation_free

	free(enc);
	free(dec);
	return 0;
}