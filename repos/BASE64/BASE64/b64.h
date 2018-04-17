#ifndef B64_H

#define B64_H 1



/**

*  Memory allocation 함수. 

*  custom function을 위해 b64_malloc과 b64_realloc을 사용할 수 있습니다. 

*/



#ifndef b64_malloc

#  define b64_malloc(ptr) malloc(ptr)

#endif

#ifndef b64_realloc

#  define b64_realloc(ptr, size) realloc(ptr, size)

#endif



/**

* Base64 index table.

*/



static const char b64_table[] = {

	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',

	'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',

	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',

	'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',

	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',

	'o', 'p', 'q', 'r', 's', 't', 'u', 'v',

	'w', 'x', 'y', 'z', '0', '1', '2', '3',

	'4', '5', '6', '7', '8', '9', '+', '/'

};



#ifdef __cplusplus

extern "C" {

#endif



	/**

	* `size_t' size인 `unsigned char *' source를 Encode하는 함수.

	* `char *' base64 encoded string을 반환합니다.

	*/



	char *

		b64_encode(const unsigned char *, size_t);



	/**

	* `size_t' size인 `char *' source를 Decode하는 함수.

	* `unsigned char *' base64 decoded string을 반환합니다.

	*/

	unsigned char *

		b64_decode(const char *, size_t);



	/**

	* `size_t' size인 'char *' source를 Decode하는 함수.

	* `unsigned char *' base64 decoded string + size of decoded string을 반홥니다.

	*/

	unsigned char *

		b64_decode_ex(const char *, size_t, size_t *);



#ifdef __cplusplus

}

#endif



#endif