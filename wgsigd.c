/* wgsigd.c - Simple server for a NAT traversal and endpoint discovery protocol for Wireguard
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

// peer_data is the database storage in memory, in the format of the response payload
// peer_ptr is the index of the next free (or oldest) slot in the array
unsigned char peer_data[keep_peers*rec_size+8+hmac_size];
unsigned int peer_ptr=0;

// search if a peer ID is in the database
// if so, out contains its record
// if not, out is zeroed
void peer_search(unsigned char peer_id[peer_id_size], unsigned char *out) {
	bzero(out, rec_size);
	for(int i=0;i<keep_peers;i++) {
		int j;
		for(j=0;j<peer_id_size && peer_data[i*rec_size+j]==peer_id[j];j++);
		if(j==peer_id_size) {
			memcpy(out, peer_data+i*rec_size, rec_size);
			return;
		}
	}
}

// update database by adding (or updating) new_peer record
void peer_replace(unsigned char new_peer[rec_size]) {
	for(int i=0;i<keep_peers;i++) {
		int j;
		for(j=0;j<peer_id_size && peer_data[i*rec_size+j]==new_peer[j];j++);
		if(j==peer_id_size) {
			// peer already in database, replace it, log and recompute HMAC of response payload
			memcpy(peer_data+i*rec_size, new_peer, rec_size);
			print_record(peer_data+i*rec_size, NULL, 0);
			hmac_sha256(peer_data+rec_size*keep_peers+8, peer_data, rec_size*keep_peers+8, secret, secret_size);
			return;
		}
	}
	// peer not in database, add it, log and recompute HMAC of response payload
	memcpy(peer_data+peer_ptr*rec_size, new_peer, rec_size);
	print_record(peer_data+peer_ptr*rec_size, NULL, 0);
	peer_ptr++;
	hmac_sha256(peer_data+rec_size*keep_peers+8, peer_data, rec_size*keep_peers+8, secret, secret_size);
}

// check if packet ok
// returns
//  0 for accepted packet
//  1 for rejected packet
int packet_ok(unsigned char *inpacket) {
		uint64_t my_time=time(NULL);
		uint64_t pkt_tai64;
		memcpy(&pkt_tai64, inpacket+pkt_counter_off, 8);
		pkt_tai64=be64toh(pkt_tai64);
		// bit 62 of TAI64 must be set (timestamp presumably after Jan 1, 1970), bit 63 unset (bit 63 set is reserved)
		if( (pkt_tai64&((uint64_t)1<<62))==0 || (pkt_tai64&((uint64_t)1<<63))!=0 ) { 
			printf("bogus inpacket TAI64 : %" PRIx64 "\n", pkt_tai64);
			return(0);
		}
		// reject packets too far in the past or in the future
		uint64_t peer_sec=pkt_tai64&(~((uint64_t)1<<62));
		if( (peer_sec > my_time+30) || (peer_sec < my_time-30) ) {
			printf("large time difference peer_sec=%" PRIx64 " my_time=%" PRIx64 "\n", peer_sec, my_time);
			return(0);
		}
		// for already known peers, check that clock is strictly increasing
		uint8_t this_peer[rec_size];
		peer_search(inpacket, this_peer);
		for(int i=0;i<rec_size;i++) {
			if(this_peer[i]) {
				memcpy(&my_time, this_peer+counter_off, 8);
				my_time=be64toh(my_time)&(~((uint64_t)1<<62));
				uint32_t my_ns=be32toh((uint32_t)this_peer[counter_off+8]);
				uint32_t peer_ns=be32toh((uint32_t)inpacket[pkt_counter_off+8]);
				if( (peer_sec<my_time) || (peer_sec==my_time && peer_ns<=my_ns) ) {
					printf("old inpacket\n");
					return(0);
				}
				break;
			}
		}
		// compute and check HMAC
		uint8_t my_hmac[32];
		hmac_sha256(my_hmac, inpacket, pkt_size-hmac_size, secret, secret_size);
		//for(int i=0;i<hmac_size;i++) printf("%x ",my_hmac[i]);printf("\n");
		//for(int i=0;i<hmac_size;i++) printf("%x ",inpacket[pkt_hmac_off+i]);printf("\n");
		if(str_nequ_ctime(my_hmac, inpacket+pkt_hmac_off)) {
			printf("wrong hmac\n");
			return(0);
		}
		return(1);
}

int main(int argc, char **argv) {
	if(argc<2) {
		printf("Usage : %s <secret_file> [<port>=%d]\n", argv[0], listen_port);
		exit(1);
	}
	read_secret(argv[1]);
	bzero(peer_data, keep_peers*rec_size+8+hmac_size);
	// prepare server socket
	unsigned int sock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	struct sockaddr_in saddr;
	bzero(&saddr, sizeof(struct sockaddr_in));
	saddr.sin_family=AF_INET;
	saddr.sin_port=htons((argc==3 ? atoi(argv[2]) : listen_port));
	saddr.sin_addr.s_addr=INADDR_ANY;
	if(bind(sock, (struct sockaddr*)&saddr, sizeof(struct sockaddr_in))) {
		perror("bind");
		exit(1);
	}
	struct sockaddr_in cl_addr;
	unsigned int cl_addrlen=sizeof(struct sockaddr_in);
	unsigned char inpacket[pkt_size];
	// loop through received datagrams
	// we do not fork as each received datagram can be processed quickly
	while(recvfrom(sock,inpacket,pkt_size,0,(struct sockaddr*)&cl_addr,&cl_addrlen)) {
		if(packet_ok(inpacket)) {
			// create record associated with this request
			unsigned char this_peer[rec_size];
			memcpy(this_peer, inpacket, peer_id_size);
			memcpy(this_peer+addr_off, &(cl_addr.sin_addr), 4);
			*(uint32_t*)(this_peer+addr_off)^=ip_mask;
			memcpy(this_peer+port_off, &(cl_addr.sin_port), 2);
			memcpy(this_peer+counter_off, inpacket+peer_id_size, 12);
			// insert record
			peer_replace(this_peer);
			// send response datagram
			if(sendto(sock,peer_data,rec_size*keep_peers+8+hmac_size,0,(struct sockaddr*)&cl_addr,cl_addrlen)<0) perror("sendto"); 
		}
	}
	perror("recvfrom");
	exit(1);
}
