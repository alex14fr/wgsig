#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <endian.h>

#define keep_peers 10
#define rec_size 50
#define peer_id_size 32
#define pkt_size 82
#define listen_port 1223
#define id_off 0
#define addr_off peer_id_size
#define port_off addr_off+4
#define counter_off port_off+2
#define pkt_id_off 0
#define pkt_counter_off peer_id_size
#define pkt_clflg_off pkt_counter_off+12
#define pkt_group_off pkt_clflg_off+2
#define pkt_hmac_off pkt_group_off+4
#define hmac_size 32
#define secret_size 32
#define ip_mask htobe32(0x322dccac)

/* base64.c */
extern void base64_encode(const unsigned char *src, size_t len, unsigned char *out);
extern void base64_decode(const unsigned char *src, size_t len, unsigned char *out);
/* hmac_sha256.c */
extern uint8_t str_nequ_ctime(uint8_t *s1, uint8_t *s2);
extern void sha256_hash(unsigned char *buf, const unsigned char *data, size_t size);
extern void hmac_sha256(uint8_t out[32], const uint8_t *data, size_t data_len, const uint8_t *key, size_t key_len);
/* common.c */
extern unsigned char secret[32];
extern void read_secret(char *f);
extern void print_record(uint8_t *rec, unsigned char *my_peer_id, uint8_t wgconf_format);
/* enc_payload.c */
extern int recvfrom_clear(int socket, uint8_t *inpacket, int clearsize, struct sockaddr *sa, socklen_t *salen, uint32_t *crypt_group);
extern int sendto_clear(int socket, uint8_t *outpacket, int clearsize, struct sockaddr *sa, socklen_t salen, uint32_t crypt_group);

