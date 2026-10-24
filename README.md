# the-cat-network-base

Server-address finder for CatGram clients. Given no configuration, it finds a
reachable `ip:port` for the messaging server by trying several independent,
redundantly-mirrored channels.

The published `servers.json` is AES-256-GCM encrypted and Ed25519 signed. Only
builds of this library can decrypt it, and only content signed by the operator's
key is accepted — a poisoned mirror, a captive portal or GitHub itself cannot
substitute addresses. Details: [docs/protocol.md](docs/protocol.md).

## Layout

| path | what |
|---|---|
| `lib/` | the library: envelope, sources, cache, resolver |
| `mobile/` | gomobile wrapper — `string`/`error` only, for Android/iOS |
| `cmd/catnetctl/` | build, sign, inspect, and resolve CLI |
| `servers.plain.json` | the plaintext payload an operator edits |
| `servers.json` | the published, encrypted and signed document |

## Operator workflow

Edit `servers.plain.json`, then:

```bash
go run ./cmd/catnetctl publish -key ~/.catnet-keys/signing-4.key -in servers.plain.json
go run ./cmd/catnetctl inspect servers.json
git commit servers.plain.json servers.json -m "catnet: update server list"
git push
```

`publish` sets `expires_at` to `issued_at + 30 days`. Re-publish before it
lapses; an expired document is still used, but flagged `stale`, and clients
will log a warning.

### Rotation

- **Address list** — edit, publish, push. Clients pick it up on next resolve.
- **Signing key** — `catnetctl keygen -kid N -out signing-N.key`, add the printed
  public key to `lib/signing.go`, publish with `-kid N`, ship a library build.
  Keep the old entry in `Keys` until no published document uses it.
- **Fetch secret** — edit `descriptorPhrase` in `lib/descriptor.go`, publish,
  ship a library build. Every client must update; there is no grace period
  because the secret is what decrypts the document.

## Using it from an app

```go
import catnet "github.com/mrfelfel/the-cat-network-base/lib"

r := catnet.Build(catnet.Options{
    Repo:      "mrfelfel/the-cat-network-base",
    CachePath: cacheDir + "/catnet-servers.json",
    Seeds:     []catnet.SeedSource{{Host: "62.220.127.238", Port: 30001}},
})
res, err := r.Resolve(ctx)
addr := res.Addrs[0] // "62.220.127.238:30001"
```

### Android (gomobile)

```bash
gomobile init
gomobile bind -target=android -o catnet.aar ./mobile
```

```kotlin
val c = mobile.New(context.cacheDir.absolutePath, "62.220.127.238:30001", 12000)
val addr = c.firstAddr(12000)   // "" + exception on total failure
val json = c.resolveJSON(12000) // full result incl. source and stale flag
```

## Layers, in order

Each layer is tried only if every earlier one failed:

| # | layer | needs |
|---|---|---|
| 0 | seed probe — parallel TCP connect to hard-coded `ip:port`, 500ms | nothing |
| 1 | static IP — GitHub raw at literal IPs, then internal mirrors | no DNS |
| 2 | encrypted DNS — DoT/DoH addressed by IP, filtered answers rejected | `8.8.8.8` / `1.1.1.1` |
| 3 | plain UDP DNS — carrier or national resolver | port 53 |
| 4 | DNS TXT `_catnet.<domain>` | DNS |
| 5 | Apps Script relay | Google reachable |

A fresh cached document returns before any of this runs; an expired one is
kept as the fallback.

`servers.json` is also the registry: it carries `github_ips`, `mirrors`,
`resolvers`, `dns_txt` and `apps_script`, so each layer learns its inputs from
the published document instead of from constants baked into the binary. The
client persists what it learned beside its cache and rebuilds the chain from it
on the next run.

`lib.Refresher` re-resolves on a timer (default 30 min, bypassing the cache) so
the cache and registry stay current whenever the network happens to be up.

## Development

```bash
go test ./... -count=1
go run ./cmd/catnetctl sources
go run ./cmd/catnetctl resolve -seeds 62.220.127.238:30001
```

Tests are hermetic — no network, no external services.

## Security notes

- The APK ships the fetch secret. A determined reverse engineer can decrypt a
  published document. This is obfuscation, not secrecy; what the signature does
  guarantee is that nobody else can *write* one.
- The seed source fetches over plain HTTP from a bare IP. That is deliberate:
  a seed must work with no DNS and no valid certificate. The signature is what
  makes the bytes trustworthy.
- Never commit `signing-*.key`. Keep it in the operator's home directory as
  `~/.catnet-keys/`, mode `0600`, or in a CI secret.
