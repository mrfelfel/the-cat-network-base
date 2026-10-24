# catnet address-finder — wire contract

This document freezes the bytes on the wire. Any change here is a **protocol
version bump** (`envelope.magic`), because shipped mobile binaries cannot be
updated on a schedule.

## 1. Goals

1. Given zero configuration, find a reachable `ip:port` for the CatGram server.
2. Survive: GitHub blocked, GitHub *mirror* blocked, HTTPS filtered, DNS
   poisoned, DNS dead entirely, app launched offline.
3. Make the published blob unreadable to a casual scraper (a single binary on a
   CDN reads as "an app asset", not "a server list").

Non-goals: hiding the server from a determined reverse engineer. The APK ships
the key material; treat this as obfuscation plus tamper-detection, not secrecy.

## 2. File format — `servers.json`

A JSON document whose binary fields are base64. It is easy to read, diff,
mirror and cache in a repository or a CDN, and every binary field is a
uniformly-encoded blob that no scraper can pattern-match on.

```json
{
  "v": 1,
  "kid": 4,
  "n": "q83vAKXbRlDg1YwJm8pQ0A==",
  "ct": "7Rf...base64...",
  "sig": "SGF2...base64..."
}
```

- `v` — protocol version, must be `1`
- `kid` — which signing keypair this blob was signed with (`0..65535`)
- `n` — 12-byte nonce, standard base64
- `ct` — ciphertext, standard base64
- `sig` — Ed25519 signature, standard base64

The signed message is derived from the *decoded bytes*, not from the JSON
text, so reformatting or reordering the JSON keys cannot break the signature:

```
prologue = "CNB1" || uint16_be(kid)           // 6 bytes
signed   = prologue || nonce || ciphertext
key      = HKDF-SHA256(DESCRIPTOR, salt = nonce, info = "catnet/v1/aead")[0:32]
plaintext= AES-256-GCM-Open(key, nonce, ct, aad = prologue)
```

- Binding `prologue` as AES-GCM AAD means an attacker cannot swap `kid` to
  select a different key.
- `kid` lets a leaked or retired keypair be revoked without shipping a new
  library: known keypairs are embedded; unknown `kid` is rejected.
- Because the signature covers bytes rather than the JSON encoding, the same
  blob can be published as pretty-printed JSON, minified, or embedded inside a
  larger file without re-signing.

## 3. Key derivation

Both keys are derived, not raw, so a snapshot of one does not yield the other
and so publishing the signing *public* key does not reveal the fetch key.

```
ikm  = HKDF-SHA256(secret = DESCRIPTOR, salt = nonce, info = "catnet/v1/aead")[0:32]
```

`DESCRIPTOR` is a 32-byte value baked into the library in obfuscated form (see
`lib/descriptor.go`). The signing keypair is generated once with
`catnetctl keygen` and its public half is embedded in `lib/signing.go`; the
private half never enters this repository (it lives in the operator's secret
store / CI secret).

## 4. Plaintext payload (JSON, UTF-8)

```json
{
  "version": 1,
  "issued_at": "2026-10-25T00:00:00Z",
  "expires_at": "2026-11-25T00:00:00Z",
  "min_lib_version": 1,
  "servers": [
    {"host": "62.220.127.238", "port": 30001, "tag": "primary", "weight": 100},
    {"host": "203.0.113.7",    "port": 30001, "tag": "backup",  "weight": 50}
  ]
}
```

Rules the library enforces after decryption **and** signature verification:

- `version == 1`
- `now < expires_at` → otherwise the blob is `stale` (still returned, flagged,
  and only used when no better source succeeded)
- `host` is either a dotted-quad IPv4 or a bare DNS name (no scheme, no path);
  `port` is `1..65535`; `weight` `0..100`, descending order preferred
- at least one server present

## 5. Sources, in attempt order

All sources return the **same bytes** for the same revision. The library
verifies signature first, so a poisoned mirror cannot substitute content.

| # | source | why it exists |
|---|---|---|
| 1 | disk cache (previous success) | offline start, instant |
| 2 | `github.com` raw (raw.githubusercontent.com) | canonical |
| 3 | operator GitHub mirror (`scorpian.ir/repos/...`) | GH blocked, mirror reachable |
| 4 | jsDelivr / ghproxy / raw.githack CDN mirrors | GH + operator mirror blocked |
| 5 | `DNS TXT _catnet.<domain>` — base64 JSON | HTTPS filtered but DNS works |
| 6 | hard-coded seed IPs (bootstrap `servers.json` served by the network itself) | DNS + HTTPS both dead |

Source 6 is the floor: the library ships 2–3 seed `ip:port` values and fetches
`/owpengram/net` from them. This is why the protocol must never require a
hostname lookup to reach the seed.

The GitHub-family sources are requested with `?t=<unix-now>` appended so that
CDN edges which cache aggressively (jsDelivr, some mirrors) do not serve a
blob older than its own `expires_at`. Sources that reject unknown query
parameters simply ignore it.

A source is "successful" only if it delivers bytes whose signature and payload
validate. Partial/truncated/CAPTIVE-PORTAL HTML responses all fail here and
fall through to the next source.

## 6. Caching

`cachePath` (caller-supplied on mobile, `$XDG_CACHE_HOME/catnet/servers.json`
otherwise) stores the last verified blob plus, in a sidecar, the `expires_at`
and the source URL that produced it. The cache is trusted for signature
verification on read; if it is corrupt it is discarded and treated as absent.
