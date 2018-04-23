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

	// SEED 알고리즘을 이용하여 암/복호화를 수행하기위한 비밀키
	unsigned char key[16] = { 0xED,0x24,0x01,0xAD, 0x22,0xFA,0x25,0x59,
								0x91,0xBA,0xFD,0xB0, 0x1F,0xEF,0xD6,0x97 };


	// CBC운영모드에서 사용되는 초기화벡터
	unsigned char iv[16] = { 0x93,0xEB,0x14,0x9F, 0x92,0xC9,0x90,0x5B,
								0xAE,0x5C,0xD3,0x4D, 0xA0,0x6C,0x3C,0x8E };


	// 암호문을 복호화한 평문을 저장할 변수
	unsigned char plaintext[10240] = {0x00, };

	// 암호문을 저장할 변수
	unsigned char ciphertext[10256] = {0x00, };
	
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

	WSADATA        wsaData;
    SOCKET         ServerSocket;   //소켓을 선언합니다.
    SOCKADDR_IN    ServerAddress;  //소켓의 주소 정보를 넣는 구조체입니다.
    unsigned short ServerPort = 5005;

	//unsigned long TempVaIL;

	char message[BUFSIZE];
	int nRcv;

    if (WSAStartup(MAKEWORD(2,2),&wsaData) == SOCKET_ERROR)
        ErrorHandling( "WSAStartup설정에서 문제 발생.\n" );

	ServerAddress.sin_family = AF_INET;
    ServerAddress.sin_addr.s_addr = inet_addr( "172.16.10.141" );
	ServerAddress.sin_port = htons( ServerPort );  //포트번호

	ServerSocket = socket(AF_INET, SOCK_STREAM,0);

	if( ServerSocket == INVALID_SOCKET ) //에러 발생시 문구 출력.
		ErrorHandling( "소켓을 생성할수 없습니다." );

	if( bind(ServerSocket,(struct sockaddr*)&ServerAddress,sizeof(ServerAddress) ) == SOCKET_ERROR ) 
        ErrorHandling( "바인드를 할 수 없습니다." );

	if( listen(ServerSocket,SOMAXCONN) == SOCKET_ERROR ) 
		ErrorHandling( "listen함수 설정을 실패했습니다.\n" );


	// socket accept
	SOCKET ClientSocket;
	SOCKADDR_IN ClientAddress;
	int AddressSize = sizeof( ClientAddress );

	printf( "서버로의 연결을 기다리고 있습니다.\n" );


	if( (ClientSocket = accept( ServerSocket,(struct sockaddr*)&ClientAddress , &AddressSize )) == INVALID_SOCKET )
		ErrorHandling( "Accept시 문제 발생.....\n" );
	else
	{
		printf("접속 IP: %s, 포트 : %d\n", inet_ntoa(ClientAddress.sin_addr), htons(ClientAddress.sin_port)) ;
		printf("시작...\n");
	}
	//CreateThread(NULL, 0, Thread, 0, 0, &TempVaIL);

	closesocket( ServerSocket ); //소켓을 닫습니다.

	//while(1){
		printf("Message Recieves ...\n");
		nRcv = recv(ClientSocket, (char*)ciphertext, sizeof(ciphertext) -1, 0);

		if(nRcv == SOCKET_ERROR){
			printf("Receive Error...\n");
			//break;
			closesocket(ClientSocket);
			WSACleanup();
			printf( "서버 프로그램이 종료 되었습니다.\n" );
			return;
		}

		ciphertext[nRcv] = '\0';

		if(strcmp((const char*)ciphertext, "exit") == 0){
			printf("Close Client Connection...\n");
			//break;
			closesocket(ClientSocket);
			WSACleanup();
			printf( "서버 프로그램이 종료 되었습니다.\n" );
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
			printf( "서버 프로그램이 종료 되었습니다.\n" );
			return;
		}

		//send(ClientSocket, message, (int)strlen(message), 0);
	//}

	closesocket(ClientSocket);

	WSACleanup();

	free(b64_dec);

	printf( "서버 프로그램이 종료 되었습니다.\n" );

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

		printf( "서버로의 연결을 기다리고 있습니다.\n" );

		if( (ClientSocket = accept( ServerSocket,(struct sockaddr*)&ClientAddress , &AddressSize )) == INVALID_SOCKET )
			ErrorHandling( "Accept시 문제 발생.....\n" );
		else
		{
			printf("접속 IP: %s, 포트 : %d\n", inet_ntoa(ClientAddress.sin_addr), htons(ClientAddress.sin_port)) ;
			printf("시작...\n");
		}
	}

	return 1;
}*/