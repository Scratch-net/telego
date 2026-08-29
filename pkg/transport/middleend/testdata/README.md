# Middle-End golden-vector provenance

The deterministic vectors in this package were generated from Telegram's
official MTProxy repository at commit
`f36d8af769ffaeac36978d38c2c0f6d1104c2137`.

The inputs are synthetic and contain no Telegram production endpoint or
registered proxy material:

- 128-byte secret containing byte values `1..128`; selector `0x04030201`.
- Server nonce `00..0f`; client nonce `f0..ff`.
- Timestamp `0x66332211`.
- IPv4 endpoints `192.0.2.10:8888` and `198.51.100.20:54321` from RFC 5737.
- IPv6 endpoints `[2001:db8::a]:8888` and `[2001:db8:1::14]:54321` from RFC 3849.

Generation used a temporary clean-room C harness outside this repository. The
harness included the official headers and called these symbols from the pinned,
compiled `objs/lib/libkdb.a`:

- `aes_create_keys` from `net/net-crypto-aes.c` for client/server IPv4 and
  client IPv6 KDF results.
- `compute_crc32` and `compute_crc32c`, backed by the official `crc32.o` and
  `crc32c.o`, for full-frame checksums.
- Official `tcp_rpc_nonce_packet`, `tcp_rpc_handshake_packet`, and constants
  from `net/net-tcp-rpc-common.h` for payload layouts.

The oracle was built and run with:

```text
make -C /tmp/telego-me-MTProxy
cc -std=gnu11 \
  -iquote /tmp/telego-me-MTProxy/common \
  -iquote /tmp/telego-me-MTProxy \
  /tmp/telego_me_official_oracle.c \
  /tmp/telego-me-MTProxy/objs/lib/libkdb.a \
  -o /tmp/telego_me_official_oracle \
  -lm -lrt -lcrypto -lz -lpthread
/tmp/telego_me_official_oracle
```

The official-object handshake and CRC32C ping frames were followed by the
required little-endian length-4 no-op frames, then encrypted as one continuous
CBC stream with the official-object client write key and IV:

```text
openssl enc -aes-256-cbc -nopad \
  -K 08449b7ce836e32835542882c26b834378d1969bbd7ee8084905769b0fe20d68 \
  -iv a4d3a131e3f8fcf613e17e9388de8593 \
  -in /tmp/telego_me_official_plaintext.bin \
  -out /tmp/telego_me_official_ciphertext.bin
```

No Telegram source code or oracle harness is copied into this package.

The stateful frame encoder and decoder start with `crc32_partial`, as assigned
by `tcp_rpcc_init_outbound` and `tcp_rpcs_init_accepted`. The sequence `-1`
handshake itself uses CRC32. `tcp_rpcc_send_handshake_packet` advertises the
local CRC32C capability. `tcp_rpcc_process_handshake_packet` rejects a peer
CRC32C response when that local capability is absent. The server intersects
the peer flag with its local default, sends only the negotiated flag in its
handshake reply, and changes `custom_crc_partial` after sending that reply.
The decoder therefore leaves a decoded sequence `-1` handshake pending until
the caller validates its process IDs and explicitly commits that exact peer
packet with the local handshake. Coalesced sequence `0` bytes remain buffered
until this commit. The codec tests enforce bilateral capability and one
transition point, and prevent per-frame checksum selection on stateful streams.

The public CBC encrypter and incremental decrypter both enforce the local
Middle-End plaintext batch cap. This keeps direct encryption calls from
bypassing the same bounded batching used by frame decoding; it is a local
safety limit, not an additional Telegram wire constant.

## Proxy RPC and client-framing vectors

The Phase 1B implementation uses the same pinned official commit and synthetic
RFC 5737/RFC 3849 addresses. The source evidence is:

- `RPC_PROXY_REQ`, `RPC_PROXY_ANS`, `RPC_CLOSE_CONN`, `RPC_CLOSE_EXT`, and
  `RPC_SIMPLE_ACK`, plus their packed fields, from
  `mtproto/mtproto-common.h` (`struct rpc_proxy_*`).
- `RPC_PING` and `RPC_PONG` from `common/rpc-const.h` and the fixed 12-byte
  implementation in `tcp_rpc_default_execute` and `tcp_rpc_send_ping` in
  `net/net-tcp-rpc-common.c`.
- IPv4-mapped IPv6 address fields and `TL_PROXY_TAG` extra data from
  `forward_tcp_query` in `mtproto/mtproto-proxy.c`.
- TL string length and zero-padding rules from `tls_string_len`,
  `tls_string_data`, and `tls_pad` in `common/tl-parse.h`.
- Abridged, intermediate, padded-intermediate, and quick-ack parsing from
  `tcp_rpcs_parse_execute` in `net/net-tcp-rpc-ext-server.c`; response framing
  and random padding from `tcp_rpc_write_packet_compact` in
  `net/net-tcp-rpc-common.c`.
- Abridged simple-ack byte swapping from `process_client_packet` in
  `mtproto/mtproto-proxy.c`.
- The encrypted envelope minimum from
  `forward_mtproto_enc_packet` in `mtproto/mtproto-proxy.c`. A temporary C
  program included the pinned official headers and printed these packed
  offsets and sizes:

```text
encrypted_message.message=56
rpc_proxy_req.data=56
rpc_proxy_ans.data=16
rpc_close_conn.size=12
rpc_close_ext.size=12
rpc_simple_ack.size=16
```

It was built and run independently of the Go package:

```text
cc -std=gnu11 -iquote /tmp/telego-me-MTProxy/common \
  -iquote /tmp/telego-me-MTProxy \
  /tmp/telego_me_official_offsets.c \
  -o /tmp/telego_me_official_offsets
/tmp/telego_me_official_offsets
```

Request and response golden vectors were also generated by the independent
MIT-licensed Python MTProxy implementation at commit
`bd5b03cd998eee5e916c5fcea8519d6d2c331d4d`. A temporary executable oracle
loaded its actual `ProxyReqStreamWriter`, `MTProtoCompactFrameStreamWriter`,
`MTProtoIntermediateFrameStreamWriter`, and
`MTProtoSecureIntermediateFrameStreamWriter` classes. It supplied fixed RFC
addresses, connection IDs, tags, payloads, and padding bytes. The command was:

```text
python3 /tmp/telego_me_python_oracle.py
```

The tagged IPv4/IPv6 request vectors and all response-framing vectors in the
tests are the oracle's direct hexadecimal output. They are not round trips
through this Go package.

The official frontend strips padded-intermediate padding before forwarding.
Its `ext_rpcs_execute` mask does not forward `RPC_F_PAD`, so DD and EE map to
the same `RPC_F_MEDIUM | RPC_F_EXTMODE2` proxy-request flags. Tests preserve
that distinction from the pinned source instead of inferring a PAD flag. The
independent Python implementation does set a PAD bit for DD requests; this is
a known oracle discrepancy, and the pinned official server source is
authoritative for that mapping.

`MAX_POST_SIZE` is `1,044,480` bytes and is assigned to the external parser's
`max_packet_len` in `mtproto/mtproto-proxy.c`. In
`tcp_rpcs_parse_execute`, the pinned server checks a padded-intermediate
packet's declared wire length against that maximum before stripping zero to
three padding bytes. `ext_rpcs_execute` checks the stripped packet again.
Response encoding may add zero to three bytes beyond an MTProto payload, but
the official inbound parser does not grant those bytes an additional size
allowance. `MAX_POST_SIZE` is not a Middle-End full-frame limit.

This package therefore uses a separate local full-frame safety cap. The cap is
the smallest value that admits an official-maximum packet in the largest
supported tagged request:

```text
1,044,480-byte RPC-forwarded client packet
+    84-byte tagged RPC_PROXY_REQ header
+    12-byte full-RPC frame overhead
= 1,044,576-byte local Middle-End frame cap
```

No Telegram implementation code was copied or transliterated.

## Client bootstrap and probe provenance

The reusable client bootstrap follows the pinned official RPC client state
machine rather than another proxy implementation:

- `tcp_rpcc_connected` and `tcp_rpcc_init_crypto` send a plaintext full frame
  numbered `-2` containing `RPC_NONCE` with IEEE CRC32.
- `tcp_rpcc_process_nonce_packet` accepts the server's matching sequence `-2`
  nonce, requires AES, checks the selected secret and the 30-second timestamp
  tolerance, then calls `tcp_rpcc_start_crypto`.
- `tcp_rpcc_start_crypto` passes the exact remote/server and local/client IP
  and port tuple to `aes_create_keys`; all following bytes use continuous
  AES-256-CBC state.
- `tcp_rpcc_send_handshake_packet` sends encrypted sequence `-1`, advertises
  `RPCF_USE_CRC32C`, identifies the local process, and supplies the remote
  endpoint pattern. `tcp_rpcc_process_handshake_packet` validates that the
  returned peer pattern matches the local process ID and rejects low-byte
  flags.
- `mtfront_pre_start` enables `TCP_RPC_IGNORE_PID` for the remote sender PID.
  The Go bootstrap therefore validates the returned peer pattern but does not
  invent a stricter remote-sender check than the official proxy client.
- CRC32C starts at sequence `0` only when both sequence `-1` handshakes carry
  `RPCF_USE_CRC32C`.
- `tcp_rpc_send_ping` and `tcp_rpc_default_execute` use a 12-byte payload made
  from the operation and one unchanged 64-bit ping ID.
- `tcp_rpcc_default_check_ready` uses a three-second handshake readiness
  timeout. The diagnostic uses the same default for its one dial, handshake,
  and ping/pong attempt; the command flag can set another explicit deadline.

The command accepts an address tuple only when it can prove its origin. A
direct link uses the exact TCP local and remote IP endpoints and requires the
remote endpoint to equal the selected artifact endpoint. A SOCKS5 link uses
the selected artifact endpoint and the CONNECT reply's exact IP
`BND.ADDR:BND.PORT`. Domain, unspecified, loopback, link-local, private,
shared-address-space, mixed-family, or zero-port tuples fail before nonce
generation and KDF. No STUN result or independently observed public address is
substituted into the KDF.
