#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include "b64.h"
#include "seedcbc.h"

#define BUFSIZE 16
#define BUFSIZE2 10240
#define ADDRESS "172.16.10.141"
#define PORT 5005

void ErrorHandling(char *message);

void main(){

	// SEED �˰����� �̿��Ͽ� ��/��ȣȭ�� �����ϱ����� ���Ű
	unsigned char key[BUFSIZE] = { 0xED,0x24,0x01,0xAD, 0x22,0xFA,0x25,0x59,
								0x91,0xBA,0xFD,0xB0, 0x1F,0xEF,0xD6,0x97 };


	// CBC���忡�� ���Ǵ� �ʱ�ȭ����
	unsigned char iv[BUFSIZE] = { 0x93,0xEB,0x14,0x9F, 0x92,0xC9,0x90,0x5B,
								0xAE,0x5C,0xD3,0x4D, 0xA0,0x6C,0x3C,0x8E };


	// ��ȣ���� ��ȣȭ�� ���� ������ ����
	unsigned char plaintext[BUFSIZE2] = {0x00, };


	// ��ȣ���� ������ ����
	unsigned char ciphertext[BUFSIZE2+16] = {0x00, };
	unsigned char ciphertext2[BUFSIZE2+16] = {0x00, };
	
	

	// ���� �޽����� ������ ����
	unsigned char message[BUFSIZE2] = {0x00, };
	

	// Base64 decoding/encoding ����
	unsigned char *b64_dec = NULL;
	char *b64_enc = NULL;

	/*
	* cipher_outlen : ��ȣ���� ���̸� ������ ����
	* plain_outlen : ���� ���̸� ������ ����
	*/
	int cipher_outlen = 0, plain_outlen = 0;

	// ���� ���̸� ������ ����
	size_t plaintext1_size = 0;

	// base64�� ���ڵ��� ������ ���̸� ������ ����
	size_t b64dec_len = 0;

	/*
	
	* nRcv : Recieve�� �޽��� ���� ����
	* AddressSize : ClientAddress size ����

	*/
	int nRcv = 0, AddressSize = 0;


	WSADATA        wsaData;
    SOCKET         ServerSocket, ClientSocket;   //������ �����մϴ�.
    SOCKADDR_IN    ServerAddress, ClientAddress; //������ �ּ� ������ �ִ� ����ü�Դϴ�.
    unsigned short ServerPort = PORT;			 // ��Ʈ ��ȣ


	// ���� �ʱ�ȭ �� 2.2���� ����
    if (WSAStartup(MAKEWORD(2,2),&wsaData) == SOCKET_ERROR)
        ErrorHandling( "WSAStartup Error.....\n" );

	// ���� ����ü�� �� ����
	ServerAddress.sin_family = AF_INET;
    ServerAddress.sin_addr.s_addr = inet_addr( ADDRESS );
	ServerAddress.sin_port = htons( ServerPort );

	// ���� ���� ����
	ServerSocket = socket(AF_INET, SOCK_STREAM,0);

	//���� �߻��� ���� ���
	if( ServerSocket == INVALID_SOCKET ) 
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

	// ���������� �ݽ��ϴ�.
	closesocket( ServerSocket ); 

	// socket receive & send
	while(1){
		printf("Message Receives ...\n");

		memset(plaintext, '\0', BUFSIZE2);
		memset(ciphertext, '\0', BUFSIZE2+16);
		memset(ciphertext2, '\0', BUFSIZE2+16);
		memset(message, '\0', BUFSIZE2);

		nRcv = recv(ClientSocket, (char*)ciphertext, sizeof(ciphertext) -1, 0);

		if(nRcv == SOCKET_ERROR){
			printf("Receive Error...\n");
			break;
		}

		ciphertext[nRcv] = '\0';

		if(strcmp((const char*)ciphertext, "exit\n") == 0){
			printf("Close Client Connection...\n");
			break;
		}

		// base64 decoding
		b64_dec = b64_decode_ex((const char*)ciphertext, strlen((const char*)ciphertext), &b64dec_len);

		// decrypt
		plain_outlen = KISA_SEED_CBC_DECRYPT(key, iv, b64_dec, b64dec_len, plaintext);

		printf("Receive Message : %s\n", ciphertext);
		printf("Receive Message Decrypt : %s\n", plaintext);

		// message making
		strncpy((char *)message, (const char*)plaintext, plain_outlen-1);
		strcat((char *)message, " received");
		
		// encrypt
		cipher_outlen = KISA_SEED_CBC_ENCRYPT(key, iv, message, strlen((const char*)message), ciphertext2);
		
		// base64 encoding
		b64_enc = b64_encode(ciphertext2, cipher_outlen);

		printf("Send Message : %s\n", message);
		printf("Send Message Encrypt : %s\n\n", b64_enc);

		send(ClientSocket, b64_enc, strlen(b64_enc), 0);

	}

	closesocket(ClientSocket);

	WSACleanup();

	free(b64_dec);
	free(b64_enc);

	printf( "The server program has been terminated.\n" );

	return;
}

void ErrorHandling(char *message){
	WSACleanup();
	fputs(message, stderr);
	fputc('\n',stderr);
	exit(1);
}
