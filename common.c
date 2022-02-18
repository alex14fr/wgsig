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

unsigned char secret[32];

void read_secret(char *f) {
	struct stat statbuf;
	// open secret file
	int fd=open(f,O_RDONLY);
	if(!fd) { printf("can't open() file %s\n", f); }
	// must be user-readable (optionally user-writable) only, regular file of 32 bytes
	int fs=fstat(fd,&statbuf);
	if(fs<0 || ( statbuf.st_mode!=(S_IFREG|S_IRUSR) && statbuf.st_mode!=(S_IFREG|S_IRUSR|S_IWUSR) )) {
		printf("file %s must be regular file, chmod 0400 or 0600\n", f);
		exit(6);
	}
	if(read(fd,secret,32)<32) { printf("secret must be 32 bytes long\n"); exit(6); }
	close(fd);
}

// dump a record in terse format or Wireguard configuration skeleton format
void print_record(uint8_t *rec, unsigned char *my_peer_id, uint8_t wgconf_format) {
	unsigned char peerid_b64[45];
	bzero(peerid_b64, 45);
	base64_encode(rec, 32, peerid_b64); 
	uint32_t ip;
	memcpy(&ip,rec+addr_off,4);
	ip^=ip_mask;
	uint16_t port;
	memcpy(&port,rec+port_off,2);
	port=ntohs(port);
	int32_t timediff;
	time_t now=time(NULL);
	uint64_t pkt_tai64;
	memcpy(&pkt_tai64,rec+peer_id_size+6,8);
	pkt_tai64=be64toh(pkt_tai64)&(~(((uint64_t)1)<<62));
	timediff=(uint64_t)now-pkt_tai64;
	if(!wgconf_format) {
		if(my_peer_id) {
			if(!memcmp(rec, my_peer_id, peer_id_size))
				printf("* ");
			else 
				printf("  ");
		}
		printf("%s %hhu.%hhu.%hhu.%hhu:%hu ", peerid_b64, (ip&255), (ip >> 8)&255, (ip >> 16)&255, (ip >> 24)&255, port);
		if(timediff)
			printf("%d\n", timediff);
		else
			printf("\n");
	} else {
		if(my_peer_id && !memcmp(rec, my_peer_id, peer_id_size)) 
			printf("# Public endpoint = %hhu.%hhu.%hhu.%hhu:%hu\n\n", (ip&255), (ip >> 8)&255, (ip >> 16)&255, (ip >> 24)&255, port);
		else 
			printf("[Peer]\n# Seen %d s ago\nPublicKey = %s\nEndpoint = %hhu.%hhu.%hhu.%hhu:%hu\n\n", timediff, peerid_b64, ip&255, (ip>>8)&255, (ip>>16)&255, (ip>>24)&255, port);
	}
}
