package ja4

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

const zeroHash = "000000000000"

func Fingerprint(handshake *tls.ClientHelloInfo) (string, error) {
	prefix, ciphers, extensions, err := sections(handshake)
	if err != nil {
		return "", err
	}

	return prefix + "_" + hashOrZero(ciphers) + "_" + hashOrZero(extensions), nil
}

func FingerprintBytes(handshake []byte) (string, error) {
	hello, err := parseClientHello(handshake)
	if err != nil {
		return "", err
	}

	return Fingerprint(hello)
}

func Raw(handshake *tls.ClientHelloInfo) (string, error) {
	prefix, ciphers, extensions, err := sections(handshake)
	if err != nil {
		return "", err
	}

	return prefix + "_" + ciphers + "_" + extensions, nil
}

func RawBytes(handshake []byte) (string, error) {
	hello, err := parseClientHello(handshake)
	if err != nil {
		return "", err
	}

	return Raw(hello)
}

func sections(handshake *tls.ClientHelloInfo) (prefix, ciphers, extensions string, err error) {
	if handshake == nil {
		return "", "", "", ErrNotClientHello
	}

	suites := stripGrease(handshake.CipherSuites)
	extensionTypes := stripGrease(handshake.Extensions)

	signatureAlgorithms := make([]uint16, 0, len(handshake.SignatureSchemes))
	for _, scheme := range handshake.SignatureSchemes {
		if !isGrease(uint16(scheme)) {
			signatureAlgorithms = append(signatureAlgorithms, uint16(scheme))
		}
	}

	var version uint16
	for _, v := range stripGrease(handshake.SupportedVersions) {
		if v > version {
			version = v
		}
	}

	prefix = "t" +
		tlsVersion(version) +
		sni(extensionTypes) +
		count(len(suites)) +
		count(len(extensionTypes)) +
		alpn(handshake.SupportedProtos)

	return prefix, cipherList(suites), extensionList(extensionTypes, signatureAlgorithms), nil
}

func cipherList(suites []uint16) string {
	return hexList(sorted(suites))
}

func extensionList(extensions, signatureAlgorithms []uint16) string {
	hashed := make([]uint16, 0, len(extensions))
	for _, extension := range extensions {
		if extension == extServerName || extension == extAlpn {
			continue
		}

		hashed = append(hashed, extension)
	}

	if len(hashed) == 0 {
		return ""
	}

	list := hexList(sorted(hashed))

	if len(signatureAlgorithms) > 0 {
		list += "_" + hexList(signatureAlgorithms)
	}

	return list
}

func sni(extensions []uint16) string {
	for _, extension := range extensions {
		if extension == extServerName {
			return "d"
		}
	}

	return "i"
}

func alpn(protocols []string) string {
	if len(protocols) == 0 || len(protocols[0]) == 0 {
		return "00"
	}

	proto := protocols[0]
	first, last := proto[0], proto[len(proto)-1]

	if !isAlphanumeric(first) || !isAlphanumeric(last) {
		encoded := hex.EncodeToString([]byte(proto))
		return string([]byte{encoded[0], encoded[len(encoded)-1]})
	}

	return string([]byte{first, last})
}

func isAlphanumeric(char byte) bool {
	return (char >= '0' && char <= '9') ||
		(char >= 'a' && char <= 'z') ||
		(char >= 'A' && char <= 'Z')
}

func isGrease(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0x00ff
}

func stripGrease(values []uint16) []uint16 {
	out := make([]uint16, 0, len(values))
	for _, v := range values {
		if !isGrease(v) {
			out = append(out, v)
		}
	}

	return out
}

func count(n int) string {
	if n > 99 {
		n = 99
	}

	return fmt.Sprintf("%02d", n)
}

func sorted(values []uint16) []uint16 {
	out := append([]uint16{}, values...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })

	return out
}

func hexList(values []uint16) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = fmt.Sprintf("%04x", v)
	}

	return strings.Join(parts, ",")
}

func hashOrZero(list string) string {
	if list == "" {
		return zeroHash
	}

	return hash12(list)
}

func hash12(s string) string {
	sum := sha256.Sum256([]byte(s))

	return hex.EncodeToString(sum[:])[:12]
}
