#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "b64.h"
#include "seedcbc.h"

// ��ȣ�� 16������ ��� �Լ�
void toHex(unsigned char *ciphertext, int cipher_outlen);

// ��ȣ�� binary�� ��� �Լ�
void ascii_as_binary(unsigned char*ciphertext, int cipher_outlen);

void main() {

	// SEED �˰����� �̿��Ͽ� ��/��ȣȭ�� �����ϱ����� ���Ű
	unsigned char key[16] = { 0xED,0x24,0x01,0xAD, 0x22,0xFA,0x25,0x59,
								0x91,0xBA,0xFD,0xB0, 0x1F,0xEF,0xD6,0x97 };


	// CBC���忡�� ���Ǵ� �ʱ�ȭ����
	unsigned char iv[16] = { 0x93,0xEB,0x14,0x9F, 0x92,0xC9,0x90,0x5B,
								0xAE,0x5C,0xD3,0x4D, 0xA0,0x6C,0x3C,0x8E };


	// ���� �Է¹��� �Լ�
	unsigned char plaintext1[10240] = {0x00, };

	// ��ȣ���� ��ȣȭ�� ���� ������ ����
	unsigned char plaintext2[10240] = {0x00, };

	// ��ȣ���� ������ ����
	unsigned char ciphertext[10256] = {0x00, };

	// Base64 encoding ����
	char *b64_enc = NULL;

	// Base64 decoding ����
	unsigned char *b64_dec = NULL;

	/*
	* cipher_outlen : ��ȣ���� ���̸� ������ ����
	* plain_outlen : ���� ���̸� ������ ����
	*/
	int cipher_outlen = 0, plain_outlen = 0;

	// ���� ���̸� ������ ����
	size_t plaintext1_size = 0;

	// base64�� ���ڵ��� ������ ���̸� ������ ����
	size_t b64dec_len = 0;


	printf("���� �Է��ϼ��� : ");
	//scanf("%10240[^\n]", &plaintext1);
	fgets((char *)plaintext1, sizeof(plaintext1), stdin);

	plaintext1_size = strlen((const char*)plaintext1);


	/*

	* SEED-CBC ��ȣȭ

	* key, iv, �Է¹���(��), �Է±���(�򹮱���), ��¹���(��ȣ��) �Է�

	* padding PKCS#7 �̿�

	* ������ ��ȣ���� ���� ��ȯ (����� 0�� ��� ��ȣȭ ����)

	*/
	cipher_outlen = KISA_SEED_CBC_ENCRYPT(key, iv, plaintext1, plaintext1_size, ciphertext);


	//base64 encoding �κ�
	b64_enc = b64_encode(ciphertext, cipher_outlen);

	//base64 decoding �κ�
	b64_dec = b64_decode_ex(b64_enc, strlen(b64_enc), &b64dec_len);

	
	/*

	* SEED-CBC ��ȣȭ

	* key, iv, �Է¹���(��ȣ��), �Է±���(��ȣ������), ��¹���(��) �Է�

	* ������ ���� ���� ��ȯ (����� 0�� ��� ��ȣȭ ����)

	*/
	plain_outlen = KISA_SEED_CBC_DECRYPT(key, iv, b64_dec, b64dec_len, plaintext2);
	

	// ciphertext(��ȣ��) ���
	toHex(ciphertext,cipher_outlen);
	ascii_as_binary(ciphertext,cipher_outlen);
	printf("\nciphertext : %s\n\n", ciphertext);
	printf("b64_encode : %s\n\n", b64_enc);
	printf("b64_decode : %s\n\n", b64_dec);


	// plaintext2(��) ���
	printf("plaintext : %s\n", plaintext2);
	
	free(b64_enc);
	free(b64_dec);

	return;
}

void toHex(unsigned char *ciphertext, int cipher_outlen){
	size_t i = 0;
	
	printf("ciphertext_hex : ");
	
	for (i = 1; i < cipher_outlen + 1; i++) 
		printf("%02X ", *(ciphertext + i - 1));

	printf("\n");

	return;
}

void ascii_as_binary(unsigned char *ciphertext, int cipher_outlen){
	int result = 0, i = 1, remainder, j, input;
	char result2[8] = {0x00, };
	int len = 0;


	printf("ciphertext_bin : ");

	
	for(j = 0; j < cipher_outlen; j++){
		input = toascii(ciphertext[j]);
		/*printf("\n%c : ", ciphertext[j]);
		printf("%d : ",input);*/
		result = 0;
		i = 1;
		while(input > 0){
			remainder = input % 2;
			result = result + (i*remainder);
			input = input/2;
			i = i*10;
		}
		itoa(result, result2,10);
		len = strlen(result2);
		while(8-len > 0){
			printf("0");
			++len;
		}
		printf("%s ", result2);
	}

	printf("\n");
	
	return;
}