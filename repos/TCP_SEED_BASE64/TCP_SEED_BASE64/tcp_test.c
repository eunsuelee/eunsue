#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <WinSock2.h>
#include "b64.h"
#include "seedcbc.h"


void ErrorHandling(char *message);

void main(){

	// SEED �˰����� �̿��Ͽ� ��/��ȣȭ�� �����ϱ����� ���Ű
	unsigned char key[16] = { 0xED,0x24,0x01,0xAD, 0x22,0xFA,0x25,0x59,
								0x91,0xBA,0xFD,0xB0, 0x1F,0xEF,0xD6,0x97 };


	// CBC���忡�� ���Ǵ� �ʱ�ȭ����
	unsigned char iv[16] = { 0x93,0xEB,0x14,0x9F, 0x92,0xC9,0x90,0x5B,
								0xAE,0x5C,0xD3,0x4D, 0xA0,0x6C,0x3C,0x8E };


	// ��ȣ���� ��ȣȭ�� ���� ������ ����
	unsigned char plaintext[10240] = {0x00, };

	// ��ȣ���� ������ ����
	unsigned char ciphertext[10256] = {0x00, };
	
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

	WSADATA        wsaData;
    SOCKET         ServerSocket, ClientSocket;   //������ �����մϴ�.
    SOCKADDR_IN    ServerAddress, ClientAddress;  //������ �ּ� ������ �ִ� ����ü�Դϴ�.
    unsigned short ServerPort = 5005;

	/*
	
	* nRcv : Recieve�� �޽��� ���� ����
	* AddressSize : ClientAddress size ����

	*/
	int nRcv, AddressSize;

	//char exit_value[7] = {0x00, };

    if (WSAStartup(MAKEWORD(2,2),&wsaData) == SOCKET_ERROR)
        ErrorHandling( "WSAStartup Error.....\n" );

	ServerAddress.sin_family = AF_INET;
    ServerAddress.sin_addr.s_addr = inet_addr( "172.16.10.141" );
	ServerAddress.sin_port = htons( ServerPort );  //��Ʈ��ȣ

	ServerSocket = socket(AF_INET, SOCK_STREAM,0);

	if( ServerSocket == INVALID_SOCKET ) //���� �߻��� ���� ���.
		ErrorHandling( "Socket Creation Error....." );

	if( bind(ServerSocket,(struct sockaddr*)&ServerAddress,sizeof(ServerAddress) ) == SOCKET_ERROR ) 
        ErrorHandling( "Bind Error......" );

	if( listen(ServerSocket,SOMAXCONN) == SOCKET_ERROR ) 
		ErrorHandling( "Listen Error.....\n" );


	// socket accept
	AddressSize = sizeof( ClientAddress );

	printf( "Waiting for connection to the server...\n" );


	if( (ClientSocket = accept( ServerSocket,(struct sockaddr*)&ClientAddress , &AddressSize )) == INVALID_SOCKET )
		ErrorHandling( "Accept Error.....\n" );
	else
	{
		printf("Connect IP: %s, Port : %d\n", inet_ntoa(ClientAddress.sin_addr), htons(ClientAddress.sin_port)) ;
		printf("Start...\n\n");
	}

	closesocket( ServerSocket ); //������ �ݽ��ϴ�.

	while(1){
		printf("Message Receives ...\n");

		memset(plaintext, '\0', 10240);
		memset(ciphertext, '\0', 10256);
		//memset(exit_value, '\0', 7);

		nRcv = recv(ClientSocket, (char*)ciphertext, sizeof(ciphertext) -1, 0);

		if(nRcv == SOCKET_ERROR){
			printf("Receive Error...\n");
			break;
		}

		ciphertext[nRcv] = '\0';

		if(strcmp((const char*)ciphertext, "exit") == 0){
			printf("Close Client Connection...\n");
			break;
		}

		b64_dec = b64_decode_ex((const char*)ciphertext, strlen((const char*)ciphertext), &b64dec_len);

		plain_outlen = KISA_SEED_CBC_DECRYPT(key, iv, b64_dec, b64dec_len, plaintext);

		printf("Receive Message : %s\n", ciphertext);
		printf("Send Message : %s\n", plaintext);

		/*if(plain_outlen == 5){
			strncpy(exit_value, (const char*)plaintext, 4);
			exit_value[4] = '\0';
		}

		if(strcmp(exit_value, "exit") == 0){
			send(ClientSocket, (const char*)exit_value, strlen(exit_value), 0);
			break;
		}*/

		send(ClientSocket, (const char*)plaintext, plain_outlen, 0);

	}

	closesocket(ClientSocket);

	WSACleanup();

	free(b64_dec);

	printf( "The server program has been terminated.\n" );

	return;
}

void ErrorHandling(char *message){
	WSACleanup();
	fputs(message, stderr);
	fputc('\n',stderr);
	getchar();
	exit(1);
}
