/* Simple client/server for a NAT traversal and endpoint discovery protocol for Wireguard
 *
 * BSD 2-Clause License
 *
 * Copyright (c) 2022, Alexandre Janon <alex14fr@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "common.h"
#include <assert.h>

#ifndef ENC_PAYLOAD
int recvfrom_clear(int socket, uint8_t *inpacket, int clearsize, struct sockaddr *sa, socklen_t *salen, uint32_t *crypt_group) {
	if(crypt_group)
		*crypt_group=0;
	return recvfrom(socket, inpacket, clearsize, 0, sa, salen);
}

int sendto_clear(int socket, uint8_t *outpacket, int clearsize, struct sockaddr *sa, socklen_t salen, uint32_t crypt_group) {
	return sendto(socket, outpacket, clearsize, 0, sa, salen);
}
#else

#include "chacha20.h"

#ifdef HAS_GETRANDOM
#include <sys/random.h>
void get_nonce(uint8_t *nonce) {
	getrandom(nonce, 12, 0);
}
#else
#ifdef HAS_ARC4RANDOM
#include <stdlib.h>
void get_nonce(uint8_t *nonce) {
	arc4random_buf(nonce, 12);
}
#else
#error "no cryptographic random number generator chosen"
#endif
#endif

static chacha_ctx chactx_i;
static uint8_t chactx_i_ok=0;

void setup_chactx(chacha_ctx *chctx) {
	if(!chactx_i_ok) {
		uint8_t shasecret[32];
		sha256_hash(shasecret, secret, 32);
		chacha_keysetup(&chactx_i, shasecret);
		chactx_i_ok=1;
	}
	memcpy(chctx, &chactx_i, sizeof(chacha_ctx));
}

int recvfrom_clear(int socket, uint8_t *inpacket, int clearsize, struct sockaddr *sa, socklen_t *salen, uint32_t *crypt_group) {
	assert(clearsize<=560);
	uint8_t inpacket_enc[577];
	int ret;
	if((ret=recvfrom(socket, inpacket_enc, clearsize+16, 0, sa, salen))<0) return(ret);
	chacha_ctx chctx;
	setup_chactx(&chctx);
	uint8_t nonce[12];
	memcpy(&nonce,inpacket_enc+4,12);
	uint32_t group;
	memcpy(&group,inpacket_enc,4);
	uint32_t gmask=(nonce[8]<<24)|(nonce[9]<<16)|(nonce[10]<<8)|nonce[11];
	group=ntohl(group)^gmask;
	if(crypt_group)
		*crypt_group=group;
	chacha_ivsetup(&chctx, nonce, 1);
	chacha_encrypt_bytes(&chctx, inpacket_enc+16, inpacket, clearsize);
	return(clearsize);
}

int sendto_clear(int socket, uint8_t *outpacket, int clearsize, struct sockaddr *sa, socklen_t salen, uint32_t crypt_group) {
	assert(clearsize<=560);
	uint8_t nonce[12];
	get_nonce(nonce);
	uint32_t gmask=(nonce[8]<<24)|(nonce[9]<<16)|(nonce[10]<<8)|nonce[11];
	uint32_t sgroup=htonl(crypt_group^gmask);
	chacha_ctx chctx;
	setup_chactx(&chctx);
	chacha_ivsetup(&chctx, nonce, 1);
	uint8_t outpacket_enc[577];
	memcpy(outpacket_enc,&sgroup,4);
	memcpy(outpacket_enc+4,&nonce,12);
	chacha_encrypt_bytes(&chctx, outpacket, outpacket_enc+16, clearsize);
	return sendto(socket, outpacket_enc, clearsize+16, 0, sa, salen);
}
#endif /* ENC_PAYLOAD */
