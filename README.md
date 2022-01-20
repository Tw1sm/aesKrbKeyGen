# aesKrbKeyGen
Script to calculate Active Directory Kerberos keys (AES256 and AES128) for an account, using its plaintext password. Either of the resulting keys can be utilized with Impacket's `getTGT.py` to obtain a TGT for the account, provided it is configured to support AES encryption.

This is a Python port of Kevin Robertson's [Get-KerberosAESKey.ps1](https://gist.github.com/Kevin-Robertson/9e0f8bfdbf4c1e694e6ff4197f0a4372)

## Examples
*__Keep in mind AD user account names are case sensitive when supplying the__ `-user` __flag__*

Calculate AES keys for a AD user account:
```
python3 aesKrbKeyGen.py -domain domain.local -user matt -pass Password1
```

Calculate AES keys for an AD computer account:
```
python3 aesKrbKeyGen.py -domain domain.local -user laptop123 -pass Password1 -host
```

Use Impacket's `getTGT.py` with a resulting AES key to obtain a TGT:
```
python3 getTGT.py domain.local/matt -aesKey <AES256/128 key>
```