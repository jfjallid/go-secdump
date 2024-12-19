// MIT License
//
// # Copyright (c) 2023 Jimmy Fjällid
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"math/bits"
	"strconv"
	"strings"
	"unicode/utf16"
)

const (
	WIN_UNKNOWN = iota
	WINXP
	WIN_SERVER_2003
	WIN_VISTA
	WIN_SERVER_2008
	WIN7
	WIN_SERVER_2008_R2
	WIN8
	WIN_SERVER_2012
	WIN81
	WIN_SERVER_2012_R2
	WIN10
	WIN_SERVER_2016
	WIN_SERVER_2019
	WIN_SERVER_2022
	WIN11
)

var aes256_constant = []byte{0x6B, 0x65, 0x72, 0x62, 0x65, 0x72, 0x6F, 0x73, 0x7B, 0x9B, 0x5B, 0x2B, 0x93, 0x13, 0x2B, 0x93, 0x5C, 0x9B, 0xDC, 0xDA, 0xD9, 0x5C, 0x98, 0x99, 0xC4, 0xCA, 0xE4, 0xDE, 0xE6, 0xD6, 0xCA, 0xE4}

var osNameMap = map[byte]string{
	WIN_UNKNOWN:        "Windows Unknown",
	WINXP:              "Windows XP",
	WIN_VISTA:          "Windows Vista",
	WIN7:               "Windows 7",
	WIN8:               "Windows 8",
	WIN81:              "Windows 8.1",
	WIN10:              "Windows 10",
	WIN11:              "Windows 11",
	WIN_SERVER_2003:    "Windows Server 2003",
	WIN_SERVER_2008:    "Windows Server 2008",
	WIN_SERVER_2008_R2: "Windows Server 2008 R2",
	WIN_SERVER_2012:    "Windows Server 2012",
	WIN_SERVER_2012_R2: "Windows Server 2012 R2",
	WIN_SERVER_2016:    "Windows Server 2016",
	WIN_SERVER_2019:    "Windows Server 2019",
	WIN_SERVER_2022:    "Windows Server 2022",
}

func GetOSVersion(currentBuild int, currentVersion float64, server bool) (os byte) {

	currentVersionStr := strconv.FormatFloat(currentVersion, 'f', 1, 64)
	if server {
		switch {
		case currentBuild >= 3790 && currentBuild < 6001:
			os = WIN_SERVER_2003
		case currentBuild >= 6001 && currentBuild < 7601:
			os = WIN_SERVER_2008
		case currentBuild >= 7601 && currentBuild < 9200:
			os = WIN_SERVER_2008_R2
		case currentBuild >= 9200 && currentBuild < 9600:
			os = WIN_SERVER_2012
		case currentBuild >= 9200 && currentBuild < 14393:
			os = WIN_SERVER_2012_R2
		case currentBuild >= 14393 && currentBuild < 17763:
			os = WIN_SERVER_2016
		case currentBuild >= 17763 && currentBuild < 20348:
			os = WIN_SERVER_2019
		case currentBuild >= 20348:
			os = WIN_SERVER_2022
		default:
			log.Debugf("Unknown server version of Windows with CurrentBuild %d and CurrentVersion %f\n", currentBuild, currentVersion)
			os = WIN_UNKNOWN
		}
	} else {
		switch currentVersionStr {
		case "5.1":
			os = WINXP
		case "6.0":
			// Windows Vista but it shares CurrentVersion and CurrentBuild with Windows Server 2008
			os = WIN_VISTA
		case "6.1":
			// Windows 7 but it shares CurrentVersion and CurrentBuild with Windows Server 2008 R2
			os = WIN7
		case "6.2":
			// Windows 8 but it shares CurrentVersion and CurrentBuild with Windows Server 2012
			os = WIN8
		case "6.3":
			// Windows 8.1 but it shares CurrentVersion and CurrentBuild with Windows Server 2012 R2
			os = WIN81
		case "10.0":
			if currentBuild < 22000 {
				os = WIN10
			} else {
				os = WIN11
			}
		default:
			log.Debugf("Unknown version of Windows with CurrentBuild %d and CurrentVersion %f\n", currentBuild, currentVersion)
			os = WIN_UNKNOWN
		}
	}

	log.Debugf("OS Version: %s\n", osNameMap[os])
	return
}

func IsWin10After1607(build int, version float64) (value bool, err error) {
	if build >= 14393 {
		value = true
	} else {
		value = false
	}
	return
}

func IsBetweenWinXPWin10(build int, version float64, isServer bool) (value bool, err error) {
	os := GetOSVersion(build, version, isServer)
	if (WINXP <= os) && (os <= WIN10) {
		value = true
	} else {
		value = false
	}
	return
}

func SHA256(key, value []byte, rounds int) []byte {
	if rounds == 0 {
		rounds = 1000
	}
	h := sha256.New()
	h.Write(key)
	for i := 0; i < 1000; i++ {
		h.Write(value)
	}
	return h.Sum(nil)
}

func DecryptAES(key, ciphertext, iv []byte) (plaintext []byte, err error) {
	nullIV := true
	var mode cipher.BlockMode
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Errorln(err)
		return
	}
	if iv != nil {
		mode = cipher.NewCBCDecrypter(block, iv)
		nullIV = false
	} else {
		iv = make([]byte, 16)
	}
	ciphertextLen := len(ciphertext)
	var cipherBuffer []byte
	for i := 0; i < ciphertextLen; i += 16 {
		if nullIV {
			mode = cipher.NewCBCDecrypter(block, iv)
		}
		// Need to calculate 16 bytes block every time and padd with 0 if not enough bytes left
		dataLeft := len(ciphertext[i:])
		if dataLeft < 16 {
			padding := 16 - dataLeft
			cipherBuffer = ciphertext[i : i+dataLeft]
			paddBuffer := make([]byte, padding)
			cipherBuffer = append(cipherBuffer, paddBuffer...)
		} else {
			cipherBuffer = ciphertext[i : i+16]
		}
		// Decryption in-place
		mode.CryptBlocks(cipherBuffer, cipherBuffer)
		plaintext = append(plaintext, cipherBuffer...)
	}
	return
}

// Wellknown function to convert 56bit to 64bit des key
// final step is to check parity and add the parity bit as the right most bit
// Not sure what the first part of this function does.
func plusOddParity(input []byte) []byte {
	output := make([]byte, 8)
	output[0] = input[0] >> 0x01
	output[1] = ((input[0] & 0x01) << 6) | (input[1] >> 2)
	output[2] = ((input[1] & 0x03) << 5) | (input[2] >> 3)
	output[3] = ((input[2] & 0x07) << 4) | (input[3] >> 4)
	output[4] = ((input[3] & 0x0f) << 3) | (input[4] >> 5)
	output[5] = ((input[4] & 0x1f) << 2) | (input[5] >> 6)
	output[6] = ((input[5] & 0x3f) << 1) | (input[6] >> 7)
	output[7] = input[6] & 0x7f
	for i := 0; i < 8; i++ {
		if (bits.OnesCount(uint(output[i])) % 2) == 0 {
			output[i] = (output[i] << 1) | 0x1
		} else {
			output[i] = (output[i] << 1) & 0xfe
		}
	}
	return output
}

func decryptNTHash(encHash, ridBytes []byte) (hash []byte, err error) {
	nt1 := make([]byte, 8)
	nt2 := make([]byte, 8)
	desSrc1 := make([]byte, 7)
	desSrc2 := make([]byte, 7)
	shift1 := []int{0, 1, 2, 3, 0, 1, 2}
	shift2 := []int{3, 0, 1, 2, 3, 0, 1}
	for i := 0; i < 7; i++ {
		desSrc1[i] = ridBytes[shift1[i]]
		desSrc2[i] = ridBytes[shift2[i]]
	}
	deskey1 := plusOddParity(desSrc1)
	deskey2 := plusOddParity(desSrc2)
	dc1, err := des.NewCipher(deskey1)
	if err != nil {
		log.Errorf("Failed to initialize first DES cipher with error: %v\n", err)
		return
	}
	dc2, err := des.NewCipher(deskey2)
	if err != nil {
		log.Errorf("Failed to initialize second DES cipher with error: %v\n", err)
		return
	}
	dc1.Decrypt(nt1, encHash[:8])
	dc2.Decrypt(nt2, encHash[8:])
	hash = append(hash, nt1...)
	hash = append(hash, nt2...)
	return
}

func DecryptRC4Hash(doubleEncHash, syskey []byte, rid uint32) (ntHash []byte, err error) {
	ridBytes := make([]byte, 4)
	encHash := make([]byte, 16)
	binary.LittleEndian.PutUint32(ridBytes, rid)
	input2 := []byte{}
	input2 = append(input2, syskey...)
	input2 = append(input2, ridBytes...)
	input2 = append(input2, s3...)
	rc4key := md5.Sum(input2)
	//log.Debugf("NT Hash RC4 encryption key: md5(%x %x %x)\n", syskey, ridBytes, s3)
	//log.Debugf("NT Hash RC4 encryption key: %x\n", rc4key)

	// Decrypt the encrypted NT Hash
	c2, err := rc4.NewCipher(rc4key[:])
	if err != nil {
		log.Errorln("Failed to init RC4 key")
		return
	}
	c2.XORKeyStream(encHash, doubleEncHash)
	ntHash, err = decryptNTHash(encHash, ridBytes)
	return
}

func DecryptAESHash(doubleEncHash, encHashIV, syskey []byte, rid uint32) (ntHash []byte, err error) {
	ridBytes := make([]byte, 4)
	encHash := make([]byte, 16)
	binary.LittleEndian.PutUint32(ridBytes, rid)
	a1, err := aes.NewCipher(syskey)
	if err != nil {
		log.Errorln("Failed to init AES key")
		return
	}
	c1 := cipher.NewCBCDecrypter(a1, encHashIV)
	c1.CryptBlocks(encHash, doubleEncHash)
	ntHash, err = decryptNTHash(encHash, ridBytes)
	return
}

func calcAES256Key(key []byte) (result []byte, err error) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Errorf("Failed to create new AES cipher with error: %s\n", err)
		return
	}
	iv := make([]byte, 16)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(key1, aes256_constant)

	block, err = aes.NewCipher(key)
	if err != nil {
		log.Errorf("Failed to create the second new AES cipher with error: %s\n", err)
		return
	}
	mode = cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(key2, key1)
	result = append(key1[:16], key2[:16]...)
	return
}

func calcAES128Key(key []byte) (result []byte, err error) {
	result = make([]byte, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Errorf("Failed to create new AES cipher with error: %s\n", err)
		return
	}
	iv := make([]byte, 16)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(result, aes256_constant[:16])
	return
}

func unicodeHexToUtf8(utf16Bytes []byte) (result string, err error) {
	if len(utf16Bytes)%2 > 0 {
		err = fmt.Errorf("Unicode (UTF 16 LE) specified, but uneven data length")
		log.Errorln(err)
		return
	}

	utf16Data := make([]uint16, len(utf16Bytes)/2)
	for i := 0; i < len(utf16Bytes); i += 2 {
		utf16Data[i/2] = uint16(utf16Bytes[i]) | uint16(utf16Bytes[i+1])<<8
	}

	utf8Str := string(utf16.Decode(utf16Data))

	return utf8Str, nil
}

func CalcMachineAESKeys(hostname, domain string, hexPass []byte) (aes128Key, aes256Key []byte, err error) {
	const ITERATIONS int = 4096 // Default for Active Directory

	domain = strings.ToUpper(domain)
	salt := fmt.Sprintf("%shost%s.%s", domain, strings.ToLower(hostname), strings.ToLower(domain))

	val, err := unicodeHexToUtf8(hexPass)
	if err != nil {
		log.Errorf("Failed to decode the MachineAccount's Unicode password: %s\n", err)
		return
	}
	passBytes := []byte(val)

	dk256 := pbkdf2.Key(passBytes, []byte(salt), ITERATIONS, 32, sha1.New)
	dk128 := dk256[:16]
	aes256Key, err = calcAES256Key(dk256)
	if err != nil {
		log.Errorln(err)
		return
	}
	aes128Key, err = calcAES128Key(dk128)
	if err != nil {
		log.Errorln(err)
		return
	}
	return
}
