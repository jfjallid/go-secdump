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
	"crypto/sha256"
	"encoding/binary"
	"math/bits"
)

const (
	WIN_UNKNOWN = iota
	WINXP
	WIN7
	WIN8
	WIN81
	WIN10
)

func GetOSVersion(build int, version float64) (os byte, err error) {

	if (build >= 7000) && (build < 7999) {
		log.Debugf("Windows 7\n")
		os = WIN7
	} else if (build >= 9000) && (build < 9999) {
		if version < 6.3 {
			log.Debugf("Windows 8\n")
			os = WIN8
		} else {
			//log.Debugf("Windows 8.1\n")
			os = WIN81
		}
	} else if (build >= 10000) && (build < 18363) {
		log.Debugf("Windows 10\n")
		os = WIN10
	} else {
		if (version < 5.2) && (version > 5.0) {
			os = WINXP
			log.Debugf("Windows XP?\n")
		} else {
			os = WIN_UNKNOWN
			log.Debugf("Unknown OS\n")
		}
	}
	log.Debugf("OS Version: %d\n", os)
	return
}

func GetOsVersionName(build int, version float64, inErr error) string {
	if inErr != nil {
		log.Errorln(inErr)
		return "Unknown OS"
	}
	os, err := GetOSVersion(build, version)
	if err != nil {
		log.Errorln(err)
		return "Unknown OS"
	}
	result := "Unknown OS"
	switch os {
	case WIN_UNKNOWN:
		break
	case WINXP:
		result = "Windows XP"
	case WIN7:
		result = "Windows 7"
	case WIN8:
		result = "Windows 8"
	case WIN81:
		result = "Windows 8.1"
	case WIN10:
		result = "Windows 10"
	}

	return result
}

func IsWin10After1607(build int, version float64, inErr error) (value bool, err error) {
	if inErr != nil {
		return false, inErr
	}
	if build >= 14393 {
		value = true
	} else {
		value = false
	}
	return
}

func IsBetweenWinXPWin10(build int, version float64, inErr error) (value bool, err error) {
	if inErr != nil {
		return false, inErr
	}
	os, err := GetOSVersion(build, version)
	if err != nil {
		return
	}
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
