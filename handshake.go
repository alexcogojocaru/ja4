package ja4

import (
	"crypto/tls"
	"errors"

	"golang.org/x/crypto/cryptobyte"
)

var (
	ErrNotClientHello                = errors.New("bytes sequence is not a ClientHello handshake")
	ErrHandshakeTruncated            = errors.New("handshake bytes sequence is truncated")
	ErrMalformedServerName           = errors.New("malformed server_name")
	ErrMalformedSupportedGroups      = errors.New("malformed supported_groups")
	ErrMalformedPointFormats         = errors.New("malformed ec_point_formats")
	ErrMalformedSignaturesAlgorithms = errors.New("malformed signature_algorithms")
	ErrMalformedAlpn                 = errors.New("malformed alpn")
	ErrMalformedSupportedVersions    = errors.New("malformed supported_versions")
)

func parseClientHello(handshake []byte) (*tls.ClientHelloInfo, error) {
	message := cryptobyte.String(handshake)

	var messageType uint8
	if !message.ReadUint8(&messageType) || messageType != handshakeClientHello {
		return nil, ErrNotClientHello
	}

	var body cryptobyte.String
	if !message.ReadUint24LengthPrefixed(&body) {
		return nil, ErrHandshakeTruncated
	}

	var legacyVersion uint16
	var sessionId, cipherSuites cryptobyte.String

	if !body.ReadUint16(&legacyVersion) ||
		!body.Skip(32) ||
		!body.ReadUint8LengthPrefixed(&sessionId) ||
		!body.ReadUint16LengthPrefixed(&cipherSuites) {
		return nil, ErrHandshakeTruncated
	}

	var suites []uint16
	for !cipherSuites.Empty() {
		var suite uint16
		if !cipherSuites.ReadUint16(&suite) {
			return nil, ErrHandshakeTruncated
		}

		suites = append(suites, suite)
	}

	var compressionMethods cryptobyte.String
	if !body.ReadUint8LengthPrefixed(&compressionMethods) {
		return nil, ErrHandshakeTruncated
	}

	hello := &tls.ClientHelloInfo{
		CipherSuites: suites,
	}

	if body.Empty() {
		hello.SupportedVersions = []uint16{legacyVersion}
		return hello, nil
	}

	var extensions cryptobyte.String
	if !body.ReadUint16LengthPrefixed(&extensions) {
		return nil, ErrHandshakeTruncated
	}

	for !extensions.Empty() {
		var extensionType uint16
		var extensionData cryptobyte.String

		if !extensions.ReadUint16(&extensionType) || !extensions.ReadUint16LengthPrefixed(&extensionData) {
			return nil, ErrHandshakeTruncated
		}

		hello.Extensions = append(hello.Extensions, extensionType)

		switch extensionType {
		case extServerName:
			var nameList cryptobyte.String
			if !extensionData.ReadUint16LengthPrefixed(&nameList) {
				return nil, ErrMalformedServerName
			}

			for !nameList.Empty() {
				var nameType uint8
				var name cryptobyte.String
				if !nameList.ReadUint8(&nameType) || !nameList.ReadUint16LengthPrefixed(&name) {
					return nil, ErrMalformedServerName
				}

				if nameType == serverNameTypeHost {
					hello.ServerName = string(name)
				}
			}

		case extSupportedGroups:
			var groupList cryptobyte.String
			if !extensionData.ReadUint16LengthPrefixed(&groupList) {
				return nil, ErrMalformedSupportedGroups
			}

			for !groupList.Empty() {
				var group uint16
				if !groupList.ReadUint16(&group) {
					return nil, ErrMalformedSupportedGroups
				}

				hello.SupportedCurves = append(hello.SupportedCurves, tls.CurveID(group))
			}

		case extPointFormats:
			var formatList cryptobyte.String
			if !extensionData.ReadUint8LengthPrefixed(&formatList) {
				return nil, ErrMalformedPointFormats
			}

			for !formatList.Empty() {
				var format uint8
				if !formatList.ReadUint8(&format) {
					return nil, ErrMalformedPointFormats
				}

				hello.SupportedPoints = append(hello.SupportedPoints, format)
			}

		case extSignatureAlgorithms:
			var algList cryptobyte.String
			if !extensionData.ReadUint16LengthPrefixed(&algList) {
				return nil, ErrMalformedSignaturesAlgorithms
			}

			for !algList.Empty() {
				var alg uint16
				if !algList.ReadUint16(&alg) {
					return nil, ErrMalformedSignaturesAlgorithms
				}

				hello.SignatureSchemes = append(hello.SignatureSchemes, tls.SignatureScheme(alg))
			}

		case extAlpn:
			var protoList cryptobyte.String
			if !extensionData.ReadUint16LengthPrefixed(&protoList) {
				return nil, ErrMalformedAlpn
			}

			for !protoList.Empty() {
				var proto cryptobyte.String
				if !protoList.ReadUint8LengthPrefixed(&proto) {
					return nil, ErrMalformedAlpn
				}

				hello.SupportedProtos = append(hello.SupportedProtos, string(proto))
			}

		case extSupportedVersions:
			var versionList cryptobyte.String
			if !extensionData.ReadUint8LengthPrefixed(&versionList) {
				return nil, ErrMalformedSupportedVersions
			}

			for !versionList.Empty() {
				var version uint16
				if !versionList.ReadUint16(&version) {
					return nil, ErrMalformedSupportedVersions
				}

				hello.SupportedVersions = append(hello.SupportedVersions, version)
			}
		}
	}

	if len(hello.SupportedVersions) == 0 {
		hello.SupportedVersions = []uint16{legacyVersion}
	}

	if !body.Empty() {
		return nil, ErrHandshakeTruncated
	}

	return hello, nil
}
