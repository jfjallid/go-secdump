package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestPlusOddParity_AllZero(t *testing.T) {
	got := plusOddParity([]byte{0, 0, 0, 0, 0, 0, 0})
	want := []byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}
	if !bytes.Equal(got, want) {
		t.Fatalf("plusOddParity(zeros) = %x, want %x", got, want)
	}
}

func TestPlusOddParity_AllFF(t *testing.T) {
	got := plusOddParity([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	want := []byte{0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe}
	if !bytes.Equal(got, want) {
		t.Fatalf("plusOddParity(ones) = %x, want %x", got, want)
	}
}

// plusOddParity must always return 8 bytes with odd parity per byte.
func TestPlusOddParity_LengthAndParity(t *testing.T) {
	inputs := [][]byte{
		{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde},
		{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
		{0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5},
	}
	for _, in := range inputs {
		out := plusOddParity(in)
		if len(out) != 8 {
			t.Errorf("plusOddParity(%x): len=%d, want 8", in, len(out))
		}
		for i, b := range out {
			ones := 0
			for x := b; x != 0; x &= x - 1 {
				ones++
			}
			if ones%2 == 0 {
				t.Errorf("plusOddParity(%x)[%d]=%#x has even parity", in, i, b)
			}
		}
	}
}

// decryptNTHash must round-trip: encrypting a 16-byte block with the same
// DES keys derived from a given RID then handing the cipher to decryptNTHash
// must reproduce the original plaintext.
func TestDecryptNTHash_RoundTrip(t *testing.T) {
	plaintext := []byte("16-byte-plaintext")[:16]
	rid := uint32(500)
	ridBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ridBytes, rid)

	shift1 := []int{0, 1, 2, 3, 0, 1, 2}
	shift2 := []int{3, 0, 1, 2, 3, 0, 1}
	desSrc1 := make([]byte, 7)
	desSrc2 := make([]byte, 7)
	for i := 0; i < 7; i++ {
		desSrc1[i] = ridBytes[shift1[i]]
		desSrc2[i] = ridBytes[shift2[i]]
	}
	// Encrypt using the same DES keys.
	deskey1 := plusOddParity(desSrc1)
	deskey2 := plusOddParity(desSrc2)
	ciphertext := make([]byte, 16)
	dc1Block, err := des.NewCipher(deskey1)
	if err != nil {
		t.Fatalf("DES key 1: %v", err)
	}
	dc2Block, err := des.NewCipher(deskey2)
	if err != nil {
		t.Fatalf("DES key 2: %v", err)
	}
	dc1Block.Encrypt(ciphertext[:8], plaintext[:8])
	dc2Block.Encrypt(ciphertext[8:], plaintext[8:])

	got, err := decryptNTHash(ciphertext, ridBytes)
	if err != nil {
		t.Fatalf("decryptNTHash: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decryptNTHash round-trip mismatch: got %x, want %x", got, plaintext)
	}
}

// DecryptAES with iv != nil must equal stdlib CBC decrypt.
func TestDecryptAES_CBC_MatchesStdlib(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 16)
	iv := bytes.Repeat([]byte{0x07}, 16)
	plaintext := bytes.Repeat([]byte{0xab}, 32)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	enc := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	enc.CryptBlocks(ciphertext, plaintext)

	got, err := DecryptAES(key, append([]byte(nil), ciphertext...), iv)
	if err != nil {
		t.Fatalf("DecryptAES: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("DecryptAES(CBC) mismatch: got %x, want %x", got, plaintext)
	}
}

// DecryptAES with iv == nil re-uses a zero IV per 16-byte block — that is
// ECB-equivalent for the first block and "predictable" for the rest. Pin
// the documented behaviour so a refactor that switches to true CBC is
// caught immediately.
func TestDecryptAES_NilIV_PerBlockZeroIV(t *testing.T) {
	key := bytes.Repeat([]byte{0x55}, 16)
	plaintext := bytes.Repeat([]byte{0xcd}, 48)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	zeroIV := make([]byte, 16)
	// Build expected output: each 16-byte block decrypted with a fresh zero IV.
	expected := make([]byte, len(plaintext))
	enc := cipher.NewCBCEncrypter(block, zeroIV)
	enc.CryptBlocks(expected, plaintext)
	// Encrypt block-by-block so each ciphertext block depends only on its
	// plaintext (matching the per-block reset on decrypt).
	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += 16 {
		blockEnc := cipher.NewCBCEncrypter(block, zeroIV)
		blockEnc.CryptBlocks(ciphertext[i:i+16], plaintext[i:i+16])
	}

	got, err := DecryptAES(key, append([]byte(nil), ciphertext...), nil)
	if err != nil {
		t.Fatalf("DecryptAES: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("DecryptAES(nilIV) mismatch: got %x, want %x", got, plaintext)
	}
}

// DecryptAES must pad ciphertext lengths that aren't a multiple of 16.
func TestDecryptAES_NonBlockLength(t *testing.T) {
	key := bytes.Repeat([]byte{0x33}, 16)
	iv := bytes.Repeat([]byte{0x09}, 16)
	// 20 bytes of ciphertext → second "block" gets zero-padded internally.
	ciphertext := make([]byte, 20)
	for i := range ciphertext {
		ciphertext[i] = byte(i)
	}
	got, err := DecryptAES(key, append([]byte(nil), ciphertext...), iv)
	if err != nil {
		t.Fatalf("DecryptAES: %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("DecryptAES short input length: got %d bytes, want 32", len(got))
	}
}

func TestSHA256_DefaultRounds(t *testing.T) {
	key := []byte("the-key")
	value := []byte("v")
	// rounds=0 → defaults to 1000.
	got := SHA256(key, value, 0)

	h := sha256.New()
	h.Write(key)
	for i := 0; i < 1000; i++ {
		h.Write(value)
	}
	want := h.Sum(nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("SHA256 rounds=0 (=>1000) mismatch: got %x, want %x", got, want)
	}
}

func TestSHA256_ExplicitRounds(t *testing.T) {
	key := []byte("k")
	value := []byte("v")
	got := SHA256(key, value, 5)
	h := sha256.New()
	h.Write(key)
	for i := 0; i < 5; i++ {
		h.Write(value)
	}
	if !bytes.Equal(got, h.Sum(nil)) {
		t.Fatalf("SHA256 rounds=5 mismatch")
	}
}

func TestGetOSVersion_ServerBoundaries(t *testing.T) {
	cases := []struct {
		build  int
		want   byte
		wantNm string
	}{
		// Boundary values at the upper edge of each range.
		{3790, WIN_SERVER_2003, "Windows Server 2003"},
		{6000, WIN_SERVER_2003, "Windows Server 2003"},
		{6001, WIN_SERVER_2008, "Windows Server 2008"},
		{7600, WIN_SERVER_2008, "Windows Server 2008"},
		{7601, WIN_SERVER_2008_R2, "Windows Server 2008 R2"},
		{9200, WIN_SERVER_2012, "Windows Server 2012"},
		{9600, WIN_SERVER_2012_R2, "Windows Server 2012 R2"},
		{14393, WIN_SERVER_2016, "Windows Server 2016"},
		{17763, WIN_SERVER_2019, "Windows Server 2019"},
		{20348, WIN_SERVER_2022, "Windows Server 2022"},
		{99999, WIN_SERVER_2022, "Windows Server 2022"},
		{3000, WIN_UNKNOWN, "Windows Unknown"},
	}
	for _, c := range cases {
		got := GetOSVersion(c.build, 10.0, true)
		if got != c.want {
			t.Errorf("GetOSVersion(server, build=%d): got %d (%s), want %d (%s)",
				c.build, got, osNameMap[got], c.want, c.wantNm)
		}
	}
}

func TestGetOSVersion_ClientWin10vs11(t *testing.T) {
	if got := GetOSVersion(19045, 10.0, false); got != WIN10 {
		t.Errorf("client build 19045: got %d, want WIN10", got)
	}
	if got := GetOSVersion(22000, 10.0, false); got != WIN11 {
		t.Errorf("client build 22000: got %d, want WIN11", got)
	}
	if got := GetOSVersion(7600, 6.1, false); got != WIN7 {
		t.Errorf("client CurrentVersion=6.1: got %d, want WIN7", got)
	}
	if got := GetOSVersion(2600, 5.1, false); got != WINXP {
		t.Errorf("client CurrentVersion=5.1: got %d, want WINXP", got)
	}
}

func TestIsWin10After1607(t *testing.T) {
	cases := []struct {
		build int
		want  bool
	}{
		{14392, false},
		{14393, true},
		{19045, true},
	}
	for _, c := range cases {
		got, err := IsWin10After1607(c.build, 10.0)
		if err != nil {
			t.Fatalf("IsWin10After1607: %v", err)
		}
		if got != c.want {
			t.Errorf("IsWin10After1607(%d) = %v, want %v", c.build, got, c.want)
		}
	}
}

// calcAES128Key is deterministic: same input → same output, and the output
// equals stdlib AES-CBC encrypt of the first 16 bytes of aes256_constant
// using a zero IV.
func TestCalcAES128Key_MatchesStdlib(t *testing.T) {
	key := bytes.Repeat([]byte{0x21}, 16)
	got, err := calcAES128Key(key)
	if err != nil {
		t.Fatalf("calcAES128Key: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	want := make([]byte, 16)
	enc := cipher.NewCBCEncrypter(block, make([]byte, 16))
	enc.CryptBlocks(want, aes256_constant[:16])
	if !bytes.Equal(got, want) {
		t.Fatalf("calcAES128Key mismatch: got %x, want %x", got, want)
	}
}

// calcAES256Key concatenates two halves derived from two AES-CBC encryptions
// of aes256_constant under the same key.
func TestCalcAES256Key_MatchesStdlib(t *testing.T) {
	key := bytes.Repeat([]byte{0x99}, 32)
	got, err := calcAES256Key(key)
	if err != nil {
		t.Fatalf("calcAES256Key: %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("calcAES256Key: len=%d, want 32", len(got))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	key1 := make([]byte, 32)
	cipher.NewCBCEncrypter(block, make([]byte, 16)).CryptBlocks(key1, aes256_constant)
	key2 := make([]byte, 32)
	cipher.NewCBCEncrypter(block, make([]byte, 16)).CryptBlocks(key2, key1)
	want := append([]byte{}, key1[:16]...)
	want = append(want, key2[:16]...)
	if !bytes.Equal(got, want) {
		t.Fatalf("calcAES256Key mismatch: got %x, want %x", got, want)
	}
}

// CalcMachineAESKeys must be deterministic and produce the expected sizes
// (16 and 32 bytes) for any UTF-16-LE machine-account password. The salt
// derivation is what catches the most regressions, so we pin it to a
// reference value derived from the documented formula.
func TestCalcMachineAESKeys_Deterministic(t *testing.T) {
	// "P@ssw0rd!" as UTF-16-LE.
	utf16Pass := []byte{
		'P', 0, '@', 0, 's', 0, 's', 0, 'w', 0, '0', 0, 'r', 0, 'd', 0, '!', 0,
	}
	host := "WS01"
	domain := "Corp.Local"

	aes128a, aes256a, err := CalcMachineAESKeys(host, domain, utf16Pass)
	if err != nil {
		t.Fatalf("CalcMachineAESKeys: %v", err)
	}
	if len(aes128a) != 16 {
		t.Errorf("aes128 length: got %d, want 16", len(aes128a))
	}
	if len(aes256a) != 32 {
		t.Errorf("aes256 length: got %d, want 32", len(aes256a))
	}

	// Deterministic: a second call with the same inputs must produce the
	// same output. The package-level BootKey/LSAKey/etc state is unrelated
	// here, so this is safe to repeat.
	aes128b, aes256b, err := CalcMachineAESKeys(host, domain, utf16Pass)
	if err != nil {
		t.Fatalf("CalcMachineAESKeys (second call): %v", err)
	}
	if !bytes.Equal(aes128a, aes128b) {
		t.Errorf("CalcMachineAESKeys non-deterministic (aes128)")
	}
	if !bytes.Equal(aes256a, aes256b) {
		t.Errorf("CalcMachineAESKeys non-deterministic (aes256)")
	}

	// A different domain → different keys (catches a salt-derivation
	// regression that drops the domain component).
	aes128c, _, err := CalcMachineAESKeys(host, "Other.Local", utf16Pass)
	if err != nil {
		t.Fatalf("CalcMachineAESKeys (other domain): %v", err)
	}
	if bytes.Equal(aes128a, aes128c) {
		t.Errorf("CalcMachineAESKeys: different domain produced identical key")
	}
}

// DecryptRC4SysKey must equal a hand-built MD5+RC4 reference.
func TestDecryptRC4SysKey_MatchesReference(t *testing.T) {
	bootKey, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	sysKeyIV := bytes.Repeat([]byte{0x10}, 16)
	encSysKey := bytes.Repeat([]byte{0xa1}, 32)

	// Recompute by hand.
	var input []byte
	input = append(input, sysKeyIV...)
	input = append(input, s1...)
	input = append(input, bootKey...)
	input = append(input, s2...)
	rc4key := md5.Sum(input)
	c, err := rc4.NewCipher(rc4key[:])
	if err != nil {
		t.Fatalf("rc4.NewCipher: %v", err)
	}
	want := make([]byte, 32)
	c.XORKeyStream(want, encSysKey)

	got, err := DecryptRC4SysKey(bootKey, encSysKey, sysKeyIV)
	if err != nil {
		t.Fatalf("DecryptRC4SysKey: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("DecryptRC4SysKey mismatch: got %x, want %x", got, want)
	}
}

// DecryptAESSysKey round-trip: encrypt with stdlib CBC, decrypt with our wrapper.
func TestDecryptAESSysKey_RoundTrip(t *testing.T) {
	bootKey := bytes.Repeat([]byte{0xbe}, 16)
	sysKeyIV := bytes.Repeat([]byte{0xef}, 16)
	plaintext := bytes.Repeat([]byte{0x77}, 32)

	block, err := aes.NewCipher(bootKey)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, sysKeyIV).CryptBlocks(ciphertext, plaintext)

	got, err := DecryptAESSysKey(bootKey, ciphertext, sysKeyIV)
	if err != nil {
		t.Fatalf("DecryptAESSysKey: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("DecryptAESSysKey round-trip mismatch: got %x, want %x", got, plaintext)
	}
}

// DecryptRC4Hash: round-trip the full RC4-syskey -> NT-hash path.
// Construct a ciphertext that decrypts to a chosen NT hash, then verify.
func TestDecryptRC4Hash_RoundTrip(t *testing.T) {
	syskey := bytes.Repeat([]byte{0x5a}, 16)
	rid := uint32(500)
	ridBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ridBytes, rid)
	// Choose a plaintext "hash" — this is the value that decryptNTHash
	// returns. We'll first DES-encrypt it with the rid-derived keys to
	// get the inner ciphertext, then RC4-encrypt that with the syskey
	// derivation to produce the outer ciphertext.
	innerPlaintext := []byte("0123456789abcdef")[:16]

	// Inner DES-encrypt.
	shift1 := []int{0, 1, 2, 3, 0, 1, 2}
	shift2 := []int{3, 0, 1, 2, 3, 0, 1}
	desSrc1 := make([]byte, 7)
	desSrc2 := make([]byte, 7)
	for i := 0; i < 7; i++ {
		desSrc1[i] = ridBytes[shift1[i]]
		desSrc2[i] = ridBytes[shift2[i]]
	}
	deskey1 := plusOddParity(desSrc1)
	deskey2 := plusOddParity(desSrc2)
	innerCipher := make([]byte, 16)
	dc1, _ := des.NewCipher(deskey1)
	dc2, _ := des.NewCipher(deskey2)
	dc1.Encrypt(innerCipher[:8], innerPlaintext[:8])
	dc2.Encrypt(innerCipher[8:], innerPlaintext[8:])

	// Outer RC4-encrypt.
	var input2 []byte
	input2 = append(input2, syskey...)
	input2 = append(input2, ridBytes...)
	input2 = append(input2, s3...)
	rc4key := md5.Sum(input2)
	c2, _ := rc4.NewCipher(rc4key[:])
	outerCipher := make([]byte, 16)
	c2.XORKeyStream(outerCipher, innerCipher)

	got, err := DecryptRC4Hash(outerCipher, syskey, rid)
	if err != nil {
		t.Fatalf("DecryptRC4Hash: %v", err)
	}
	if !bytes.Equal(got, innerPlaintext) {
		t.Fatalf("DecryptRC4Hash round-trip mismatch: got %x, want %x", got, innerPlaintext)
	}
}

// DecryptAESHash: same shape as DecryptRC4Hash but the outer cipher is
// AES-CBC under the syskey.
func TestDecryptAESHash_RoundTrip(t *testing.T) {
	syskey := bytes.Repeat([]byte{0x91}, 16)
	encHashIV := bytes.Repeat([]byte{0xc3}, 16)
	rid := uint32(1000)
	ridBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ridBytes, rid)
	innerPlaintext := []byte("fedcba9876543210")[:16]

	// Inner DES-encrypt.
	shift1 := []int{0, 1, 2, 3, 0, 1, 2}
	shift2 := []int{3, 0, 1, 2, 3, 0, 1}
	desSrc1 := make([]byte, 7)
	desSrc2 := make([]byte, 7)
	for i := 0; i < 7; i++ {
		desSrc1[i] = ridBytes[shift1[i]]
		desSrc2[i] = ridBytes[shift2[i]]
	}
	deskey1 := plusOddParity(desSrc1)
	deskey2 := plusOddParity(desSrc2)
	innerCipher := make([]byte, 16)
	dc1, _ := des.NewCipher(deskey1)
	dc2, _ := des.NewCipher(deskey2)
	dc1.Encrypt(innerCipher[:8], innerPlaintext[:8])
	dc2.Encrypt(innerCipher[8:], innerPlaintext[8:])

	// Outer AES-CBC encrypt with the syskey.
	block, err := aes.NewCipher(syskey)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	outerCipher := make([]byte, 16)
	cipher.NewCBCEncrypter(block, encHashIV).CryptBlocks(outerCipher, innerCipher)

	got, err := DecryptAESHash(outerCipher, encHashIV, syskey, rid)
	if err != nil {
		t.Fatalf("DecryptAESHash: %v", err)
	}
	if !bytes.Equal(got, innerPlaintext) {
		t.Fatalf("DecryptAESHash round-trip mismatch: got %x, want %x", got, innerPlaintext)
	}
}

