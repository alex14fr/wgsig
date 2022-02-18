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
	unsigned char peerid_b64[44];
	bzero(peerid_b64, 44);
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
		if(my_peer_id && !memcmp(rec, my_peer_id, peer_id_size))
			printf("* ");
		else if(my_peer_id)
			printf("  ");
		printf("%s %d.%d.%d.%d:%d ", peerid_b64, (ip&255), (ip >> 8)&255, (ip >> 16)&255, (ip >> 24)&255, port);
		if(timediff)
			printf("%d\n", timediff);
		else
			printf("\n");
	} else {
		if(my_peer_id && !memcmp(rec, my_peer_id, peer_id_size)) 
			printf("# Public endpoint = %d.%d.%d.%d:%d\n\n", (ip&255), (ip >> 8)&255, (ip >> 16)&255, (ip >> 24)&255, port);
		else 
			printf("[Peer]\n# Seen %d s ago\nPublicKey = %s\nEndpoint = %d.%d.%d.%d:%d\n\n", timediff, peerid_b64, ip&255, (ip>>8)&255, (ip>>16)&255, (ip>>24)&255, port);
	}
}
