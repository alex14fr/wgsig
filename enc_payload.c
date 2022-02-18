#include "common.h"

#ifndef ENC_PAYLOAD
int recvfrom_clear(int socket, uint8_t *inpacket, int clearsize, struct sockaddr *sa, socklen_t *salen, uint32_t *crypt_group) {
	if(crypt_group)
		*crypt_group=0;
	return recvfrom(socket, inpacket, clearsize, 0, sa, salen);
}

int sendto_clear(int socket, uint8_t *outpacket, int clearsize, struct sockaddr *sa, socklen_t salen) {
	return sendto(socket, outpacket, clearsize, 0, sa, salen);
}
#else

#include "chacha20.h"

#ifdef HAS_GETRANDOM
#include <sys/random.h>
void get_nonce(uint8_t *nonce) {
	getrandom(nonce, 32, 0);
}
#else
#ifdef HAS_ARC4RANDOM
#include <stdlib.h>
void get_nonce(uint8_t *nonce) {
	arc4random_buf(nonce, 32);
}
#else
#error "no cryptographic random number generator chosen"
#endif
#endif


#endif /* ENC_PAYLOAD */
