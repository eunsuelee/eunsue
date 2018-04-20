#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "b64.h"
#include "seedcbc.h"

// 암호문 16진수로 출력 함수
void print_cipher(unsigned char *ciphertext, int cipher_outlen){
	size_t i = 0;
	
	printf("ciphertext_hex : ");
	
	for (i = 1; i < cipher_outlen + 1; i++) 
		printf("%02X ", *(ciphertext + i - 1));
	
	printf("\n");
}



void main() {

	// SEED 알고리즘을 이용하여 암/복호화를 수행하기위한 비밀키
	unsigned char key[16] = { 0xED,0x24,0x01,0xAD, 0x22,0xFA,0x25,0x59,
								0x91,0xBA,0xFD,0xB0, 0x1F,0xEF,0xD6,0x97 };


	// CBC운영모드에서 사용되는 초기화벡터
	unsigned char iv[16] = { 0x93,0xEB,0x14,0x9F, 0x92,0xC9,0x90,0x5B,
								0xAE,0x5C,0xD3,0x4D, 0xA0,0x6C,0x3C,0x8E };


	// 평문을 입력받을 함수
	unsigned char plaintext1[10240] = {0x00, };

	// 암호문을 복호화한 평문을 저장할 변수
	unsigned char plaintext2[10240] = {0x00, };

	// 암호문을 저장할 변수
	unsigned char ciphertext[10256] = {0x00, };

	// Base64 encoding 변수
	char *b64_enc = NULL;

	// Base64 decoding 변수
	unsigned char *b64_dec = NULL;

	/*
	* cipher_outlen : 암호문의 길이를 저장할 변수
	* plain_outlen : 평문의 길이를 저장할 변수
	*/
	int cipher_outlen = 0, plain_outlen = 0;

	// 평문의 길이를 저장할 변수
	size_t plaintext1_size = 0;

	// base64로 디코딩된 문장의 길이를 저장할 변수
	size_t b64dec_len = 0;


	printf("평문을 입력하세요 : ");
	//scanf("%10240[^\n]", &plaintext1);
	fgets((char *)plaintext1, sizeof(plaintext1), stdin);

	plaintext1_size = strlen((const char*)plaintext1);


	/*

	* SEED-CBC 암호화

	* key, iv, 입력버퍼(평문), 입력길이(평문길이), 출력버퍼(암호문) 입력

	* padding PKCS#7 이용

	* 생성된 암호문의 길이 반환 (결과가 0일 경우 암호화 실패)

	*/
	cipher_outlen = KISA_SEED_CBC_ENCRYPT(key, iv, plaintext1, plaintext1_size, ciphertext);


	//base64 encoding 부분
	b64_enc = b64_encode(ciphertext, cipher_outlen);

	//base64 decoding 부분
	b64_dec = b64_decode_ex(b64_enc, strlen(b64_enc), &b64dec_len);

	
	/*

	* SEED-CBC 복호화

	* key, iv, 입력버퍼(암호문), 입력길이(암호문길이), 출력버퍼(평문) 입력퍄

	* 생성된 평문의 길이 반환 (결과가 0일 경우 복호화 실패)

	*/
	plain_outlen = KISA_SEED_CBC_DECRYPT(key, iv, b64_dec, b64dec_len, plaintext2);
	

	// ciphertext(암호문) 출력
	/*print_cipher(ciphertext,cipher_outlen);
	printf("ciphertext : %s\n", ciphertext);
	printf("cipher_b64 : %s\n", b64_enc);
	printf("b64_decode : %s\n", b64_dec);
*/

	printf("plain_len : %d\n", plain_outlen);
	// plaintext2(평문) 출력
	printf("plaintext : %s\n", plaintext2);
	
	free(b64_enc);
	free(b64_dec);

	return;
}