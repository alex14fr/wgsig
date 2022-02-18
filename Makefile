CFLAGS = -O3 -Wall -D_BSD_SOURCE -std=c99
LDFLAGS = -s
O = .

#Uncomment one of the following to enable encrypted payloads
CFLAGS += -DENC_PAYLOAD -DHAS_GETRANDOM    # Linux
#CFLAGS += -DENC_PAYLOAD -DHAS_ARC4RANDOM   # BSD

BINS = $(O)/wgsigd $(O)/wgsigc
COMMON_OBJ = $(O)/base64.o $(O)/hmac_sha256.o $(O)/enc_payload.o $(O)/common.o

all: $(O) $(BINS)

PROTOCOL.txt: PROTOCOL.html
	lynx -dump PROTOCOL.html > $@

$(O):
	mkdir $(O)

$(O)/%.o: %.c common.h chacha20.h
	$(CC) -c $(CFLAGS) -o $@ $<

$(O)/wgsigd: $(O)/wgsigd.o $(COMMON_OBJ)
	$(CC) $(LDFLAGS) -o $@ $(O)/wgsigd.o $(COMMON_OBJ)

$(O)/wgsigc: $(O)/wgsigc.o $(COMMON_OBJ)
	$(CC) $(LDFLAGS) -o $@ $(O)/wgsigc.o $(COMMON_OBJ)

clean:
	rm -f $(BINS) $(COMMON_OBJ) $(O)/wgsigd.o $(O)/wgsigc.o

