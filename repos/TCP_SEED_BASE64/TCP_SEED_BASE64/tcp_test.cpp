#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <WinSock2.h>
#include <process.h>
#include "b64.h"
#include "seedcbc.h"

#define BUFSIZE 10256

void ErrorHandling(char *message);

//unsigned long __stdcall Thread(void *arg);

//SOCKET         ServerSocket, ClientSocket;

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
    SOCKET         ServerSocket;   //������ �����մϴ�.
    SOCKADDR_IN    ServerAddress;  //������ �ּ� ������ �ִ� ����ü�Դϴ�.
    unsigned short ServerPort = 5005;

	//unsigned long TempVaIL;

	char message[BUFSIZE];
	int nRcv;

    if (WSAStartup(MAKEWORD(2,2),&wsaData) == SOCKET_ERROR)
        ErrorHandling( "WSAStartup�������� ���� �߻�.\n" );

	ServerAddress.sin_family = AF_INET;
    ServerAddress.sin_addr.s_addr = inet_addr( "172.16.10.141" );
	ServerAddress.sin_port = htons( ServerPort );  //��Ʈ��ȣ

	ServerSocket = socket(AF_INET, SOCK_STREAM,0);

	if( ServerSocket == INVALID_SOCKET ) //���� �߻��� ���� ���.
		ErrorHandling( "������ �����Ҽ� �����ϴ�." );

	if( bind(ServerSocket,(struct sockaddr*)&ServerAddress,sizeof(ServerAddress) ) == SOCKET_ERROR ) 
        ErrorHandling( "���ε带 �� �� �����ϴ�." );

	if( listen(ServerSocket,SOMAXCONN) == SOCKET_ERROR ) 
		ErrorHandling( "listen�Լ� ������ �����߽��ϴ�.\n" );


	// socket accept
	SOCKET ClientSocket;
	SOCKADDR_IN ClientAddress;
	int AddressSize = sizeof( ClientAddress );

	printf( "�������� ������ ��ٸ��� �ֽ��ϴ�.\n" );


	if( (ClientSocket = accept( ServerSocket,(struct sockaddr*)&ClientAddress , &AddressSize )) == INVALID_SOCKET )
		ErrorHandling( "Accept�� ���� �߻�.....\n" );
	else
	{
		printf("���� IP: %s, ��Ʈ : %d\n", inet_ntoa(ClientAddress.sin_addr), htons(ClientAddress.sin_port)) ;
		printf("����...\n");
	}
	//CreateThread(NULL, 0, Thread, 0, 0, &TempVaIL);

	closesocket( ServerSocket ); //������ �ݽ��ϴ�.

	//while(1){
		printf("Message Recieves ...\n");
		nRcv = recv(ClientSocket, (char*)ciphertext, sizeof(ciphertext) -1, 0);

		if(nRcv == SOCKET_ERROR){
			printf("Receive Error...\n");
			//break;
			closesocket(ClientSocket);
			WSACleanup();
			printf( "���� ���α׷��� ���� �Ǿ����ϴ�.\n" );
			return;
		}

		ciphertext[nRcv] = '\0';

		if(strcmp((const char*)ciphertext, "exit") == 0){
			printf("Close Client Connection...\n");
			//break;
			closesocket(ClientSocket);
			WSACleanup();
			printf( "���� ���α׷��� ���� �Ǿ����ϴ�.\n" );
			return;
		}

		b64_dec = b64_decode_ex((const char*)ciphertext, strlen((const char*)ciphertext), &b64dec_len);

		plain_outlen = KISA_SEED_CBC_DECRYPT(key, iv, b64_dec, b64dec_len, plaintext);

		printf("Receive Message : %s", ciphertext);
		printf("\nSend Message : %s", plaintext);
		gets(message);
		if(strcmp(message, "exit") == 0){
			//send(ClientSocket, (const char*)plaintext, (int)strlen((const char*)plaintext), 0);
			//break;
			closesocket(ClientSocket);
			WSACleanup();
			free(b64_dec);
			printf( "���� ���α׷��� ���� �Ǿ����ϴ�.\n" );
			return;
		}

		//send(ClientSocket, message, (int)strlen(message), 0);
	//}

	closesocket(ClientSocket);

	WSACleanup();

	free(b64_dec);

	printf( "���� ���α׷��� ���� �Ǿ����ϴ�.\n" );

	return;
}

void ErrorHandling(char *message){
	WSACleanup();
	fputs(message, stderr);
	fputc('\n',stderr);
	getchar();
	//_getch();
	exit(1);
}

/*unsigned long __stdcall Thread(void *arg){
	while(1){
		SOCKET ClientSocket;
		SOCKADDR_IN ClientAddress;
		int AddressSize = sizeof( ClientAddress );

		printf( "�������� ������ ��ٸ��� �ֽ��ϴ�.\n" );

		if( (ClientSocket = accept( ServerSocket,(struct sockaddr*)&ClientAddress , &AddressSize )) == INVALID_SOCKET )
			ErrorHandling( "Accept�� ���� �߻�.....\n" );
		else
		{
			printf("���� IP: %s, ��Ʈ : %d\n", inet_ntoa(ClientAddress.sin_addr), htons(ClientAddress.sin_port)) ;
			printf("����...\n");
		}
	}

	return 1;
}*/