package ja4

import "crypto/tls"

const handshakeClientHello = 0x01

const serverNameTypeHost = 0x00

const (
	extServerName          = 0x0000
	extSupportedGroups     = 0x000a
	extPointFormats        = 0x000b
	extSignatureAlgorithms = 0x000d
	extAlpn                = 0x0010
	extSupportedVersions   = 0x002b
)

func tlsVersion(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "13"
	case tls.VersionTLS12:
		return "12"
	case tls.VersionTLS11:
		return "11"
	case tls.VersionTLS10:
		return "10"
	}

	return "00"
}
