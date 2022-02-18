# wgsigc wgsigd - (Wireguard signalling client, Wireguard signalling daemon)
## Implementation of a NAT traversal and endpoint discovery protocol for Wireguard

Author: Alexandre Janon `<alex14fr at gmail dot com>`

Project page: <https://github.com/alex14fr/wgsig/>

License: 2-clause BSD for wgsigc.c and wgsigd.c

wgsigc and wgsigd are simple implementations of a subset of the
protocol described in <https://github.com/alex14fr/wgsig/raw/master/PROTOCOL.txt>.

### Goal and prerequisites

This protocol can be used to simplify configuration of the public keys and endpoints 
(IPv4 addresses, port numbers) of the (possibly cone NATed) Wireguard peers.

The daemon has to be runned on a "publicly reachable" server, with a routable IP or hostname known to the clients, and a fixed UDP port.

A single 32-byte secret key must be pre-shared between all the clients and the server.

### Requirements

Client and server programs are written in C99, use POSIX interface with endian(3)/byteorder(3) BSD extensions in <endian.h>, with no other dependencies.

Hardware and bandwidth requirements are very small: on an `x86_64` musl Linux host, for a statically-linked, fully stripped, -O2 compiled sizes are

```
   text    data     bss     dec     hex filename
	51118     600    2792   54510    d4ee wgsigc
	28221     592    2384   31197    79dd wgsigd
```

The server do not perform any dynamic memory allocation. The only dynamic allocation by the client is caused by the DNS resolver (getaddrinfo(3)).

Each client request generates two UDP datagrams, one in each direction. The request payload has 82 bytes, the response payload (by default) has 540 bytes.


### How to use:

 - Compile:

```
   $ make
```

 - Generate a 32-byte secret key, and set appropriate permissions:

```
   $ dd if=/dev/random of=secret bs=1 count=32
   $ chmod 0600 secret
```

 - On each peer, copy secret with the appropriate permissions, and, if not already done, generate your Wireguard private key and extract public key:

```
   $ wg genkey > private
	$ wg pubkey < private > wg_pubkey
```

 - Launch the server on UDP port 1223 using "secret" as secret file:

```
   $ ./wgsigd secret 1223
```

 - On each peer, launch client on port 10000 (use even-numbered port) with:

```
   $ ./wgsigc server-hostname 1223 $(cat wg_pubkey) secret 10000
```

A skeleton wg(8) configuration will be generated on standard output:

```
[Peer]
# Seen 1889 s ago
PublicKey = S0RuxWTj3PQPYfTAo545Vm6EF+VfPgVs/H2VCGqhewk=
Endpoint = 150.55.88.93:4135

[Peer]
# Seen 102 s ago
PublicKey = KXtAZFocpNKmqv53vDZstBKPE3IRq3TghtY6c//yzmc=
Endpoint = 201.57.242.12:4115

# Public endpoint = 14.56.88.94:53679

[Interface]
ListenPort = 10000
```

 - Also send regular requests to update your information about the peers. Use a different, odd-numbered client source port so as not to update the port number used for WireGuard packets.

```
   $ ./wgsigc server-hostname 1223 $(cat wg_pubkey) secret 10001

	[ ... Updated WireGuard configuration skeleton follows ... ]
```

### Limitations (with respect to documented protocol), might be removed one day:

 - encrypted payload not supported
 - GROUP is ignored and replaced with 0
 - only one response datagram is sent, limiting the number of managed peers to 10; to overcome this limitation in a dirty way, one can increase the keep_peers macro definition in common.h; this (slightly) increases memory consumption, break compatibility with the documented protocol, and clients/server compiled with a different value of keep_peers, and may break when UDP datagrams larger than 576-byte payloads are not supported
 - client does not discard old records returned by server


