# Artifact fixture provenance

These deterministic fixtures model the public responses from Telegram's
`getProxyConfig` and `getProxyConfigV6` endpoints. They contain only RFC 5737
IPv4 and RFC 3849 IPv6 documentation addresses. Tests construct the opaque
secret as a deterministic byte sequence; no production secret, endpoint, tag,
or proxy credential is stored in this repository.

The grammar and limits were derived clean-room from Telegram's official
MTProxy repository at commit
`f36d8af769ffaeac36978d38c2c0f6d1104c2137`:

- `README.md` names `getProxySecret` and `getProxyConfig`, and recommends
  updating the config once per day. The pinned README does not name a V6
  endpoint.
- `common/parse-config.c` defines comments, whitespace, and the 16 MiB config
  input limit.
- `mtproto/mtproto-config.c` defines `default`, `proxy`, and `proxy_for`, accepts
  the complete signed-int16 cluster range including zero, and applies a fully
  parsed replacement only after a successful validation pass.
- `mtproto/mtproto-config.h` caps unique clusters at 1024 and targets at 4096.
- `net/net-crypto-aes.h` and `net/net-crypto-aes.c` define the opaque secret's
  accepted 32..256-byte range.

The `getProxyConfigV6` URL and its response format are independent public
endpoint observations, not claims about the pinned README. A bounded fetch on
2026-08-29 returned numeric IPv6 `proxy_for` entries for signed IDs `+/-1`
through `+/-5`, with no `default` or `+/-203` entries. The IPv4 response also
published `+/-203`. These inventories describe that response and these
fixtures; the parser does not treat them as a permanent allowlist or readiness
requirement. Positive, negative, zero, and other signed-int16 IDs remain
distinct, as they do in the official cluster lookup.

No Telegram source code was copied or transliterated.
