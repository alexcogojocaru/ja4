# ja4

Go library for generating JA4 fingerprints from ClientHello messages. (ServerHello will be added in a future version)

## Install

```
go get github.com/alexcogojocaru/ja4
```

## Usage

From a `*tls.ClientHelloInfo`, as handed to a TLS server:

```go
server := &tls.Config{
	GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		fingerprint, err := ja4.Fingerprint(hello)
		if err != nil {
			return nil, err
		}

		log.Printf("client=%s ja4=%s", hello.ServerName, fingerprint)

		return nil, nil
	},
}
```

From raw handshake bytes — a packet capture, an eBPF program, a sniffed
connection. The input starts at the handshake type byte, with the 5-byte TLS
record header already stripped:

```go
fingerprint, err := ja4.FingerprintBytes(handshake)
// t13d3112h2_e8f1e7e78f70_b26ce05bbdd6
```

Both paths produce the same fingerprint for the same handshake.

`Raw` and `RawBytes` return the unhashed form, `JA4_r`. It is not a fingerprint —
it is what you read when yours disagrees with another implementation:

```
t13d3112h2_002f,0033,0035,...,ccaa_000a,000b,...,0033_0403,0503,...,0602
```

## The fingerprint

```
t13d3112h2_e8f1e7e78f70_b26ce05bbdd6
```

Three sections. The first is readable:

| | |
|---|---|
| `t` | transport — TCP |
| `13` | TLS version, taken from `supported_versions` |
| `d` | a domain was requested (`i` for a bare IP) |
| `31` | cipher suite count |
| `12` | extension count |
| `h2` | first and last character of the first ALPN value |

The second is a SHA-256 of the sorted cipher list, truncated to 12 characters.
The third is a SHA-256 of the sorted extension list followed by the signature
algorithms, also truncated to 12.

Three details in there are easy to get wrong and produce a fingerprint that
looks valid and matches nothing:

- **GREASE values are stripped everywhere.** Clients inject reserved values
  (RFC 8701) at random on every connection, so a fingerprint that kept them
  would differ every connection.
- **`server_name` and `alpn` are counted but not hashed.** They vary by
  destination, and the fingerprint has to stay stable across the sites one
  client visits.
- **Signature algorithms are not sorted.** Cipher and extension order is
  shuffled per connection and gets normalised away; signature algorithm order
  is itself a trait of the stack.

## Notes

`Fingerprint` does its own GREASE filtering, because `crypto/tls` does not strip
GREASE from `ClientHelloInfo`. Nothing is required of the caller.

The parser accepts arbitrary bytes from the network and validates every
length prefix before reading. Malformed input returns an error; it never panics.

## License

MIT — see [LICENSE](LICENSE).

JA4 itself is a specification by FoxIO, published under the
[FoxIO License 1.1](https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE), which
restricts use to non-commercial purposes. This library is an independent
implementation, but if you are considering commercial use, read those terms
first.
