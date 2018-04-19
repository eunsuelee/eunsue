#include <stdio.h>
#include "seedcbc.h"


void main() {

	// SEED �˰����� �̿��Ͽ� ��/��ȣȭ�� �����ϱ����� ���Ű
	unsigned char key[16] = { 0xED,0x24,0x01,0xAD, 0x22,0xFA,0x25,0x59,
		0x91,0xBA,0xFD,0xB0, 0x1F,0xEF,0xD6,0x97 };


	// CBC���忡�� ���Ǵ� �ʱ�ȭ����
	unsigned char iv[16] = { 0x93,0xEB,0x14,0x9F, 0x92,0xC9,0x90,0x5B,
		0xAE,0x5C,0xD3,0x4D, 0xA0,0x6C,0x3C,0x8E };


	// ��
	unsigned char plaintext1[128] = { 0xB4,0x0D,0x70,0x03, 0xD9,0xB6,0x90,0x4B,
		0x35,0x62,0x27,0x50, 0xC9,0x1A,0x24,0x57,
		0x5B,0xB9,0xA6,0x32, 0x36,0x4A,0xA2,0x6E,
		0x3A,0xC0,0xCF,0x3A, 0x9C,0x9D,0x0D,0xCB };


	// ��ȣ���� ��ȣȭ�� ���� ������ ����
	unsigned char plaintext2[128];

	// ��ȣ���� ������ ����
	unsigned char ciphertext[144];

	/*
	* outlne1 : ��ȣ���� ���̸� ������ ����
	* outlen2 : ���� ���̸� ������ ����
	*/
	int outlen1, outlen2;

	// ���� ���̸� ������ ����
	size_t plaintext_size = strlen(plaintext1);

	/*

	* SEED-CBC ��ȣȭ

	* key, iv, �Է¹���(��), �Է±���(�򹮱���), ��¹���(��ȣ��) �Է�

	* ������ ��ȣ���� ���� ��ȯ (����� 0�� ��� ��ȣȭ ����)

	*/
	outlen1 = KISA_SEED_CBC_ENCRYPT(key, iv, plaintext1, plaintext_size, ciphertext);

	/*

	* SEED-CBC ��ȣȭ

	* key, iv, �Է¹���(��ȣ��), �Է±���(��ȣ������), ��¹���(��) �Է�

	* ������ ���� ���� ��ȯ (����� 0�� ��� ��ȣȭ ����)

	*/
	outlen2 = KISA_SEED_CBC_DECRYPT(key, iv, ciphertext, outlen1, plaintext2);




	// ciphertext(��ȣ��) ���
	printf("ciphertext : \n");

	for (size_t i = 1; i < outlen1 + 1; i++) {
		printf("%02X ", *(ciphertext + i - 1));


		if (i % 16 == 0)
			printf("\n");
		else if (i % 4 == 0)
			printf("	");


	}

	printf("\n");

	// plaintext(��) ���

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