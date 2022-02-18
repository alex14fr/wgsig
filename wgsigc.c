/* wgsigc.c - Simple client for a NAT traversal and endpoint discovery protocol for Wireguard
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
#include <netdb.h>

int main(int argc, char **argv) {
	if(argc<6) {
		printf("Usage : %s <remote_host> <remote_port> <base64_peerid> <secret_file> <local_port>\n", argv[0]);
		exit(0);
	}
	if(strlen(argv[3])!=44) {
		printf("peerid must be 44 chars long\n");
		exit(0);
	}
	// read Group secret from supplied file
	read_secret(argv[4]);
	// base64-decode Peer ID
	unsigned char my_id[32];
	base64_decode((unsigned char*)argv[3],44,my_id);
	// resolve remote hostname
	struct addrinfo *ai;
	getaddrinfo(argv[1],NULL,NULL,&ai);
	for( ; ai && ai->ai_family!=AF_INET ; ai=ai->ai_next );
	if(!ai) {
		printf("%s not found\n", argv[1]);
		exit(0);
	}
	freeaddrinfo(ai);
	// prepare connection to remote server
	unsigned int sock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	struct sockaddr_in laddr;
	bzero(&laddr, sizeof(struct sockaddr_in));
	laddr.sin_family=AF_INET;
	laddr.sin_port=htons(atoi(argv[5]));
	laddr.sin_addr.s_addr=INADDR_ANY;
	if(bind(sock,(struct sockaddr*)&laddr,sizeof(struct sockaddr_in))) {
		perror("bind");
		exit(1);
	}
	struct sockaddr_in saddr;
	bzero(&saddr, sizeof(struct sockaddr_in));
	saddr.sin_family=AF_INET;
	saddr.sin_port=htons(atoi(argv[2]));
	saddr.sin_addr.s_addr=(((struct sockaddr_in*)(ai->ai_addr))->sin_addr).s_addr;
	// prepare request datagram
	uint8_t outpacket[pkt_size];
	bzero(outpacket, pkt_size);
	memcpy(outpacket, my_id, 32); 
	struct timespec tp;
	clock_gettime(CLOCK_REALTIME,&tp);
	// TAI64 generation: we set the 62nd bit and convert endianness
	uint64_t tai64=htobe64(tp.tv_sec|((uint64_t)1<<62));
	uint32_t tns=htobe32((uint32_t)tp.tv_nsec);
	*(uint64_t*)(outpacket+pkt_counter_off)=tai64;
	*(uint32_t*)(outpacket+pkt_counter_off+8)=tns; 
	hmac_sha256(outpacket+pkt_hmac_off, outpacket, pkt_size-hmac_size, secret, secret_size);
	//for(int i=0;i<pkt_size;i++) { printf("%x ",outpacket[i]); } printf("\n");
	// send request datagram
	if(sendto(sock,outpacket,pkt_size,0,(struct sockaddr*)&saddr,sizeof(struct sockaddr_in))<0) {
		perror("sendto");
		exit(1);
	}
	// receive response datagram(s)
	uint8_t inpacket[keep_peers*rec_size+8+hmac_size];
	unsigned int addrlen=sizeof(struct sockaddr_in);
	uint8_t endrecv=0;
	while(!endrecv) {
		if(recvfrom(sock,inpacket,keep_peers*rec_size+8+hmac_size,0,(struct sockaddr*)&saddr,&addrlen)<0) {
			perror("recvfrom");
			exit(1);
		}
		// verify response HMAC
		uint8_t hmac[32];
		hmac_sha256(hmac, inpacket, keep_peers*rec_size+8, secret, secret_size);
		if(str_nequ_ctime(hmac, inpacket+keep_peers*rec_size+8)) {
			printf("received datagram with wrong hmac\n");
		} else {
			endrecv=1;
			// loop through response records
			for(int i=0;i<keep_peers;i++) {
				for(int j=0;j<rec_size;j++) {
					if(inpacket[i*rec_size+j]) {
						// found non-zero record, print corresponding Wireguard configuration
						print_record(inpacket+i*rec_size, my_id, 1);
						break;
					}
				}
			}
			printf("[Interface]\nListenPort = %d\n", atoi(argv[5]));
		}
	}
}
