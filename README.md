ssoDecrypt
==========

ssoDecrypt is a small tool for decrypting Oracle (local) autologin wallets (cwallet.sso).
Only 11g wallets are currently supported.

Oracle autologin wallets are integrated in several Oracle productions and used for

* Certificates (HTTP Server, Internet Directory, ... )
* Secure External Password Store
* Advanced Security Option (ASO)
* ...

##  Requirements

* [Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files](http://www.oracle.com/technetwork/java/javase/downloads/index.html).
* ["oks" (includes also required BouncyCastle Crypto lib](http://soonerorlater.hu/index.khtml?article_id=516) 

## Usage

1.  Patch JRE with JCE Unlimited Strength Jurisdiction Policy
2.  Download PoC from soonerorlater.hu (see "oks" requirement) and copy the content of the "oks" folder into ssoDecryptor/libs/
3.  Compile

    <pre>
    javac -cp .:libs/:libs/bcprov-jdk16-145.jar ssoDecryptor.java
    </pre>

4.  Run:
     <pre>
    ./ssoDecrypt.sh /path/to/cwallet.sso [<username> <hostname>]
    </pre>


The username and hostnames arguments are for the local SSO wallet 
(see "Background" for more infos). 


## Convert SSO Wallet to a normal PKCS#12 file

The SSO wallet key in raw format should be written into a file (cwallet.key) to be binary safe.
#### Get key and copy cwallet.sso to newP12wallet.p12 without SSO header (first 77 bytes):

<pre>
[oracle@server ~]$ ./ssoDecrypt.sh /path/to/cwallet.sso
sso key: 7f76ebcc0b326c81
sso secret: 52d76a43e5dd847053cdeb0f1dd3ed6a8d1bead0c0de9747
obfuscated password: 07344b6c491f24470956332c68164657
p12 password (hex): 37472315037178586d7728675d677c73
[...]

[oracle@server ~]$ echo 37472315037178586d7728675d677c73 | xxd -p -r > cwallet.key 
[oracle@server ~]$ dd if=/path/to/cwallet.sso of=newP12wallet.p12 bs=1 skip=77
[oracle@server ~]$ openssl pkcs12 -in newP12wallet.p12 -nodes -passin file:cwallet.key 
MAC verified OK
[...]
</pre>

#### Then change the password of the new PKCS#12 wallet
<pre>
[oracle@server ~]$ orapki wallet change_pwd -wallet newP12wallet.p12 -oldpwd `cat cwallet.key` -newpwd test1234
[oracle@server ~]$ openssl pkcs12 -in newP12wallet.p12 -nodes -passin pass:test1234
MAC verified OK
[...]
</pre>


## Background
#### File structure of 11g cwallet.sso
<pre>
0x00 - 0x4C     Header:
    0x00 - 0x02     First 3 bytes are always A1 F8 4E (wallet recognition?!)
    0x03            Type = SSO: 36; LSSO: 38
    0x04 - 0x06     00 00 00
    0x07            Version (10g: 05; 11g:  06)
    0x08 - 0x0A     00 00 00
    0x0B - 0x0C     11g: always the same (41 35)
    0x0D - 0x1C     DES key
    0x1D - 0x4C     DES secret (DES -> CBC -> PKCS7 padding) which contains the PKCS#12 password
0x4D - EOF      PKCS#12 data (ASN.1 block)
</pre>

#### Local SSO wallet
In the local SSO wallet version (-auto_login_local), the decrypted DES secret is a 
message which needs to be hashed (HMAC SHA1) with a key to get the actual 
PKCS#12 password.
This key is made up of username and hostname of the corresponding system 
where the wallet was created. If the key is unknown it is not possible to 
open the local SSO wallet.


