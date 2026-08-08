package ja4

import (
	"crypto/tls"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	curlTLS13Hex = "" +
		"010001fc03031b6219a0629d46d288be94d79a684b82af761917f03f16d90e49" +
		"6bf82365830e2095f98e70ab52360889a5945fd25d203a8a55809364c9653b0b" +
		"705bad7f5ce510003e130213031301c02cc030009fcca9cca8ccaac02bc02f00" +
		"9ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d00" +
		"3c0035002f00ff0100017500000010000e00000b6578616d706c652e636f6d00" +
		"0b000403000102000a00160014001d0017001e00190018010001010102010301" +
		"040010000e000c02683208687474702f312e3100160000001700000031000000" +
		"0d002a0028040305030603080708080809080a080b0804080508060401050106" +
		"01030303010302040205020602002b00050403040303002d0002010100330026" +
		"0024001d0020755b3adefaddf774db23d0d4f537a1bf84ad61b27518515386c2" +
		"3b3a99879757001500b600000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000"

	curlTLS12Hex = "" +
		"010000d50303cadeb01d34bf015e50712a26392c2b90e5fbe1156fc6b5458e72" +
		"32abc17eeec8000038c02cc030009fcca9cca8ccaac02bc02f009ec024c02800" +
		"6bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00" +
		"ff0100007400000010000e00000b6578616d706c652e636f6d000b0004030001" +
		"02000a000c000a001d0017001e001900180010000e000c02683208687474702f" +
		"312e310016000000170000000d002a0028040305030603080708080809080a08" +
		"0b080408050806040105010601030303010302040205020602"

	curlJA4 = "t13d3112h2_e8f1e7e78f70_b26ce05bbdd6"

	curlRaw = "t13d3112h2_" +
		"002f,0033,0035,0039,003c,003d,0067,006b,009c,009d,009e,009f,00ff," +
		"1301,1302,1303,c009,c00a,c013,c014,c023,c024,c027,c028,c02b,c02c," +
		"c02f,c030,cca8,cca9,ccaa_" +
		"000a,000b,000d,0015,0016,0017,002b,002d,0031,0033_" +
		"0403,0503,0603,0807,0808,0809,080a,080b,0804,0805,0806,0401,0501," +
		"0601,0303,0301,0302,0402,0502,0602"
)

func handshake(t *testing.T, encoded string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(encoded)
	require.NoError(t, err)

	return decoded
}

func curlHello() *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		ServerName: "example.com",
		CipherSuites: []uint16{
			0x1302, 0x1303, 0x1301, 0xc02c, 0xc030, 0x009f, 0xcca9, 0xcca8,
			0xccaa, 0xc02b, 0xc02f, 0x009e, 0xc024, 0xc028, 0x006b, 0xc023,
			0xc027, 0x0067, 0xc00a, 0xc014, 0x0039, 0xc009, 0xc013, 0x0033,
			0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0x00ff,
		},
		SupportedCurves: []tls.CurveID{
			0x001d, 0x0017, 0x001e, 0x0019, 0x0018,
			0x0100, 0x0101, 0x0102, 0x0103, 0x0104,
		},
		SupportedPoints: []uint8{0x00, 0x01, 0x02},
		SignatureSchemes: []tls.SignatureScheme{
			0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b,
			0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0303, 0x0301,
			0x0302, 0x0402, 0x0502, 0x0602,
		},
		SupportedProtos:   []string{"h2", "http/1.1"},
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
		Extensions: []uint16{
			0x0000, 0x000b, 0x000a, 0x0010, 0x0016, 0x0017,
			0x0031, 0x000d, 0x002b, 0x002d, 0x0033, 0x0015,
		},
	}
}

func TestFingerprintWithClientHelloInfo(t *testing.T) {
	fingerprint, err := Fingerprint(curlHello())

	require.NoError(t, err)
	assert.Equal(t, curlJA4, fingerprint)
}

func TestRawWithClientHelloInfo(t *testing.T) {
	raw, err := Raw(curlHello())

	require.NoError(t, err)
	assert.Equal(t, curlRaw, raw)
}

func TestFingerprintBytes(t *testing.T) {
	fingerprint, err := FingerprintBytes(handshake(t, curlTLS13Hex))

	require.NoError(t, err)
	assert.Equal(t, curlJA4, fingerprint)
}

func TestFingerprintBytesTLS12(t *testing.T) {
	fingerprint, err := FingerprintBytes(handshake(t, curlTLS12Hex))

	require.NoError(t, err)
	assert.Equal(t, "t12d2807h2_d943125447b4_a44c6288192a", fingerprint)
}

func TestBothInputsAgree(t *testing.T) {
	fromBytes, err := parseClientHello(handshake(t, curlTLS13Hex))
	require.NoError(t, err)

	fromInfo := curlHello()

	assert.Equal(t, fromInfo.ServerName, fromBytes.ServerName)
	assert.Equal(t, fromInfo.CipherSuites, fromBytes.CipherSuites)
	assert.Equal(t, fromInfo.SupportedCurves, fromBytes.SupportedCurves)
	assert.Equal(t, fromInfo.SupportedPoints, fromBytes.SupportedPoints)
	assert.Equal(t, fromInfo.SignatureSchemes, fromBytes.SignatureSchemes)
	assert.Equal(t, fromInfo.SupportedProtos, fromBytes.SupportedProtos)
	assert.Equal(t, fromInfo.SupportedVersions, fromBytes.SupportedVersions)
	assert.Equal(t, fromInfo.Extensions, fromBytes.Extensions)
}

func TestGreaseIsStripped(t *testing.T) {
	hello := curlHello()
	hello.CipherSuites = append([]uint16{0x3a3a}, hello.CipherSuites...)
	hello.Extensions = append([]uint16{0x0a0a}, hello.Extensions...)
	hello.SignatureSchemes = append([]tls.SignatureScheme{0x5a5a}, hello.SignatureSchemes...)
	hello.SupportedVersions = append([]uint16{0x2a2a}, hello.SupportedVersions...)

	fingerprint, err := Fingerprint(hello)

	require.NoError(t, err)
	assert.Equal(t, curlJA4, fingerprint,
		"GREASE must not change the fingerprint")
}

func TestIsGrease(t *testing.T) {
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0xfafa} {
		assert.True(t, isGrease(v), "%#04x should be GREASE", v)
	}

	for _, v := range []uint16{0x1301, 0x002f, 0x0a0b, 0x1a2a, 0x3a0a, 0x0000} {
		assert.False(t, isGrease(v), "%#04x should not be GREASE", v)
	}
}

func TestSniIsIWithoutServerName(t *testing.T) {
	hello := curlHello()
	hello.ServerName = ""
	hello.Extensions = []uint16{
		0x000b, 0x000a, 0x0010, 0x0016, 0x0017,
		0x0031, 0x000d, 0x002b, 0x002d, 0x0033, 0x0015,
	}

	fingerprint, err := Fingerprint(hello)

	require.NoError(t, err)
	assert.Equal(t, "t13i3111h2", fingerprint[:10])
}

func TestAlpn(t *testing.T) {
	for _, tc := range []struct {
		protocols []string
		expected  string
	}{
		{nil, "00"},
		{[]string{""}, "00"},
		{[]string{"h2"}, "h2"},
		{[]string{"http/1.1"}, "h1"},
		{[]string{"h2", "http/1.1"}, "h2"},
		{[]string{"q"}, "qq"},
		{[]string{"\x00\xab"}, "0b"},
		{[]string{"\xe9x"}, "e8"},
		{[]string{"\xaa\xbb"}, "ab"},
		{[]string{"-h2-"}, "2d"},
	} {
		assert.Equal(t, tc.expected, alpn(tc.protocols), "alpn(%q)", tc.protocols)
	}
}

func TestParseRejectsNonClientHello(t *testing.T) {
	_, err := FingerprintBytes([]byte{0x02, 0x00, 0x00, 0x00})

	assert.ErrorIs(t, err, ErrNotClientHello)
}

func TestTruncatedNeverPanics(t *testing.T) {
	full := handshake(t, curlTLS13Hex)

	for i := 0; i < len(full); i++ {
		_, err := FingerprintBytes(full[:i])
		assert.Error(t, err, "hello truncated to %d/%d bytes parsed cleanly", i, len(full))
	}
}

func foxioReferenceHello() *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		ServerName: "example.com",
		CipherSuites: []uint16{
			0x3a3a, 0x1301, 0xc02b, 0x009c, 0xcca9, 0x002f, 0xc030, 0x1303,
			0x009d, 0xc013, 0x1302, 0xcca8, 0xc02c, 0x0035, 0xc014, 0xc02f,
		},
		SignatureSchemes: []tls.SignatureScheme{
			0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
		},
		SupportedProtos:   []string{"h2", "http/1.1"},
		SupportedVersions: []uint16{0x2a2a, 0x0304, 0x0303},
		Extensions: []uint16{
			0x0a0a, 0x0017, 0x0000, 0xff01, 0x000a, 0x0010, 0x000b, 0x0023,
			0x0005, 0x000d, 0x0012, 0x0033, 0x002d, 0x002b, 0x001b, 0x0015,
			0x4469, 0x1a1a,
		},
	}
}

func TestFingerprintMatchesFoxIOReferenceVector(t *testing.T) {
	fingerprint, err := Fingerprint(foxioReferenceHello())

	require.NoError(t, err)
	assert.Equal(t, "t13d1516h2_8daaf6152771_e5627efa2ab1", fingerprint)
}

func TestRawMatchesFoxIOReferenceVector(t *testing.T) {
	raw, err := Raw(foxioReferenceHello())

	require.NoError(t, err)
	assert.Equal(t, "t13d1516h2_"+
		"002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_"+
		"0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_"+
		"0403,0804,0401,0503,0805,0501,0806,0601", raw)
}

func TestRawBytes(t *testing.T) {
	raw, err := RawBytes(handshake(t, curlTLS13Hex))

	require.NoError(t, err)
	assert.Equal(t, curlRaw, raw)
}

func TestNilClientHelloInfo(t *testing.T) {
	_, err := Fingerprint(nil)

	assert.ErrorIs(t, err, ErrNotClientHello)
}
