// catnetctl builds, signs and inspects the published servers.json document.
//
//	catnetctl keygen -kid 4 -out signing-4.key
//	catnetctl publish -key signing-4.key -kid 4 -in servers.plain.json -out servers.json
//	catnetctl inspect servers.json
//	catnetctl resolve -repo mrfelfel/the-cat-network-base
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	catnet "github.com/mrfelfel/the-cat-network-base/lib"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = cmdKeygen(os.Args[2:])
	case "publish":
		err = cmdPublish(os.Args[2:])
	case "inspect":
		err = cmdInspect(os.Args[2:])
	case "resolve":
		err = cmdResolve(os.Args[2:])
	case "sources":
		fs := flag.NewFlagSet("sources", flag.ExitOnError)
		rf := bindResolverFlags(fs)
		_ = fs.Parse(os.Args[2:])
		for _, s := range buildResolver(fs, rf).Sources() {
			fmt.Println(s)
		}
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "catnetctl: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "catnetctl:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `catnetctl — catnet address-finder tooling

commands:
  keygen   -kid N -out signing-N.key
  publish  -key FILE -kid N -in PLAINTEXT.json [-out servers.json] [-ttl 720h]
  inspect  FILE
  resolve  -repo owner/name [-seeds ip:port,ip:port]
  sources  -repo owner/name
`)
}

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	kid := fs.Uint("kid", 0, "signing key id (0..65535)")
	out := fs.String("out", "", "output PEM file (private key)")
	force := fs.Bool("force", false, "overwrite an existing file")
	_ = fs.Parse(args)
	if *out == "" {
		return errors.New("keygen: -out is required")
	}
	if *kid > 65535 {
		return errors.New("keygen: -kid must be 0..65535")
	}
	if _, err := os.Stat(*out); err == nil && !*force {
		return fmt.Errorf("keygen: %s exists (use -force)", *out)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(*out, block, 0o600); err != nil {
		return err
	}
	fmt.Printf("kid=%d\nprivate_key_pem=%s\npublic_key_hex=%s\npublic_key_b64=%s\n",
		*kid, *out, hex.EncodeToString(pub), base64.StdEncoding.EncodeToString(pub))
	fmt.Printf("\nAdd this to lib/signing.go:\n  KeyID: ed25519.PublicKey{%s},\n", goByteList(pub))
	return nil
}

func cmdPublish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ExitOnError)
	keyPath := fs.String("key", "", "PEM private key")
	kid := fs.Uint("kid", uint(catnet.KeyID), "signing key id")
	in := fs.String("in", "servers.plain.json", "plaintext payload JSON")
	out := fs.String("out", "servers.json", "output document")
	ttl := fs.Duration("ttl", 30*24*time.Hour, "expires_at = issued_at + ttl (0 keeps the input's value)")
	_ = fs.Parse(args)

	priv, err := loadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	var payload catnet.Payload
	if err := strictUnmarshal(raw, &payload); err != nil {
		return fmt.Errorf("publish: %s: %w", *in, err)
	}
	if *ttl > 0 {
		if payload.IssuedAt.IsZero() {
			payload.IssuedAt = time.Now().UTC().Truncate(time.Minute)
		}
		payload.ExpiresAt = payload.IssuedAt.Add(*ttl)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	desc := catnet.Descriptor()
	defer func() {
		for i := range desc {
			desc[i] = 0
		}
	}()
	doc, err := catnet.SealEnvelope(payload, nonce, desc, uint16(*kid), priv)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, append(doc, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d bytes, kid=%d, %d servers, expires %s)\n",
		*out, len(doc)+1, *kid, len(payload.Servers), payload.ExpiresAt.UTC().Format(time.RFC3339))
	return nil
}

func cmdInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("inspect: exactly one file required")
	}
	raw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	env, err := catnet.ParseEnvelope(raw, catnet.Descriptor(), catnet.Keys)
	if err != nil {
		return err
	}
	p := env.Payload
	fmt.Printf("version   %d\nissued    %s\nexpires   %s\nservers   %d\n",
		p.Version, p.IssuedAt.UTC().Format(time.RFC3339), p.ExpiresAt.UTC().Format(time.RFC3339), len(p.Servers))
	for _, s := range p.Sorted() {
		fmt.Printf("  %-22s %-10s weight=%d\n", s.Addr(), s.Tag, s.Weight)
	}
	if p.Expired(time.Now()) {
		fmt.Println("\nWARNING: expired")
	}
	return nil
}

func cmdResolve(args []string) error {
	fs := flag.NewFlagSet("resolve", flag.ExitOnError)
	r := bindResolverFlags(fs)
	_ = fs.Parse(args)
	ctx, cancel := contextWithSignal()
	defer cancel()
	res, err := buildResolver(fs, r).Resolve(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("source    %s\nstale     %v\nservers   %d\n", res.Source, res.Stale, len(res.Servers))
	for _, s := range res.Servers {
		fmt.Printf("  %-22s %-10s weight=%d\n", s.Addr(), s.Tag, s.Weight)
	}
	if len(res.Attempts) > 0 {
		fmt.Println("attempts:")
		for _, a := range res.Attempts {
			if a.Err != nil {
				fmt.Printf("  %-40s %v\n", a.Source, a.Err)
			}
		}
	}
	return nil
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("-key is required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("%s: not PEM", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an Ed25519 key", path)
	}
	return priv, nil
}

func goByteList(b []byte) string {
	s := ""
	for i, v := range b {
		if i%8 == 0 {
			s += "\n\t\t"
		}
		s += fmt.Sprintf("0x%02x, ", v)
	}
	return s
}
