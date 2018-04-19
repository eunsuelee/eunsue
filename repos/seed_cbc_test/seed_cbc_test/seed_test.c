#include <stdio.h>
#include "seedcbc.h"


void main() {

	// SEED 알고리즘을 이용하여 암/복호화를 수행하기위한 비밀키
	unsigned char key[16] = { 0xED,0x24,0x01,0xAD, 0x22,0xFA,0x25,0x59,
		0x91,0xBA,0xFD,0xB0, 0x1F,0xEF,0xD6,0x97 };


	// CBC운영모드에서 사용되는 초기화벡터
	unsigned char iv[16] = { 0x93,0xEB,0x14,0x9F, 0x92,0xC9,0x90,0x5B,
		0xAE,0x5C,0xD3,0x4D, 0xA0,0x6C,0x3C,0x8E };


	// 평문
	unsigned char plaintext1[128] = { 0xB4,0x0D,0x70,0x03, 0xD9,0xB6,0x90,0x4B,
		0x35,0x62,0x27,0x50, 0xC9,0x1A,0x24,0x57,
		0x5B,0xB9,0xA6,0x32, 0x36,0x4A,0xA2,0x6E,
		0x3A,0xC0,0xCF,0x3A, 0x9C,0x9D,0x0D,0xCB };


	// 암호문을 복호화한 평문을 저장할 변수
	unsigned char plaintext2[128];

	// 암호문을 저장할 변수
	unsigned char ciphertext[144];

	/*
	* outlne1 : 암호문의 길이를 저장할 변수
	* outlen2 : 평문의 길이를 저장할 변수
	*/
	int outlen1, outlen2;

	// 평문의 길이를 저장할 변수
	size_t plaintext_size = strlen(plaintext1);

	/*

	* SEED-CBC 암호화

	* key, iv, 입력버퍼(평문), 입력길이(평문길이), 출력버퍼(암호문) 입력

	* 생성된 암호문의 길이 반환 (결과가 0일 경우 암호화 실패)

	*/
	outlen1 = KISA_SEED_CBC_ENCRYPT(key, iv, plaintext1, plaintext_size, ciphertext);

	/*

	* SEED-CBC 복호화

	* key, iv, 입력버퍼(암호문), 입력길이(암호문길이), 출력버퍼(평문) 입력

	* 생성된 평문의 길이 반환 (결과가 0일 경우 복호화 실패)

	*/
	outlen2 = KISA_SEED_CBC_DECRYPT(key, iv, ciphertext, outlen1, plaintext2);




	// ciphertext(암호문) 출력
	printf("ciphertext : \n");

	for (size_t i = 1; i < outlen1 + 1; i++) {
		printf("%02X ", *(ciphertext + i - 1));


		if (i % 16 == 0)
			printf("\n");
		else if (i % 4 == 0)
			printf("	");


	}

	printf("\n");

	// plaintext(평문) 출력

	printf("plaintext1 : ");

	for (size_t i = 0; i < plaintext_size; i++)
		printf("%02X ", *(plaintext1 + i));

	printf("\n");

	printf("plaintext2 : ");

	for (size_t i = 0; i < outlen2; i++)
		printf("%02X ", *(plaintext2 + i));

	printf("\n");


	return;
}