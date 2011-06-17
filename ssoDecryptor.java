import java.util.Enumeration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import javax.crypto.Mac;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;


import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import oks.OracleKeyStore;


public class ssoDecryptor 
{
    // self initialization
    private static ssoDecryptor ssoD = new ssoDecryptor();
    
    // content of the wallet file
    private byte[] walletSSO        = null;
    private byte[] walletP12        = null;
    private String walletSSOheader  = null;
    
    // specifies if the wallet was created as -auto_login_local
    private boolean localSSO = false;


    public static void main (String argv[]) 
		throws NoSuchAlgorithmException
    {
		// Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files are required
		// download from Oracle: http://www.oracle.com/technetwork/java/javase/downloads/index.html
		if( Cipher.getMaxAllowedKeyLength("AES") < 256 ) {
			System.err.println("Error: JCE - Unlimited Strength Jurisdiction Policy Files are required");
			System.exit(1);
		}
    
        String username = null;
        String hostname = null;
        
        // check arguments
        if (argv.length == 3) {
            username = argv[1];
            hostname = argv[2];
        } else if (argv.length != 1) {
            System.err.println("Usage: java ssoDecryptor /path/to/cwallet.sso [<username> <hostname>]");
            System.exit(1);
        }
        
        ssoD.listWalletDetails( argv[0], username, hostname );
    }
    
    // list wallet key and the containing secrets
    //      username and hostname are for encrypting local wallets
    private void listWalletDetails ( String filePath, String username, String hostname ) 
    {
        try {
            // load SSO wallet into byte[]
            walletSSO = readFileIntoByteArray( filePath );
            
            // get the SSO header (with the PKCS#12 password) and PKCS#12 part
            walletP12 = new byte[ walletSSO.length - 77 ];
            System.arraycopy( walletSSO, 77, walletP12, 0, walletP12.length );
            walletSSOheader = getSSOheader();

            // check the wallet version
            switch ( getSSOVersion() ) {
                case 1:
                    System.err.println("10g SSO wallet isn't supported yet");
                    break; 
                case 2:
                    // get the respective details which will be required for decrypting the wallet
                    byte[] SSOkey       = getSSOkey();
                    byte[] SSOsecret    = getSSOsecret();
                    byte[] password     = decryptP12pwd( SSOkey, SSOsecret );
                    byte[] password_ob  = null;
                              
                    // deobfuscate the password if this is a local SSO wallet
                    if ( localSSO == true ) {
                        password_ob = password;
                        password = deobLSSOpassword(password, username, hostname);   
                    }
                    
                    // check if the extracted password works and output the details
                    if ( checkWallet(password) ) {
                            System.out.println( "sso key: " + toHex( SSOkey ) );
                            System.out.println( "sso secret: " + toHex( SSOsecret ) ); 
                            if ( localSSO == true) {
                                System.out.println( "obfuscated password: " + toHex( password_ob ) );
                            }
                            System.out.println( "p12 password (hex): " + toHex( password ) );
                            System.out.println( "--------------------------------------------------------" );
                            
                            // decrypt the wallet with the extracted password
                            getContent(password);
                    } else {
                        System.err.println("PKCS12 key store mac invalid - wrong password, wrong LSSO secret (username + hostname) or corrupted file.");
                    }

                    break;
                default:
                    System.err.println("Unknown wallet version");
            }
        } catch (IOException e)  {
            System.err.println( "Error in reading SSO wallet:" );
            e.printStackTrace();
        } 
        
    }
    
    // get master keys and db logins from wallet
    private void getContent(byte[] password)
    {
        // create an inputstream out of the PKCS#12 file in byte[]
        InputStream is = new ByteArrayInputStream( walletP12 );   
             
        try {
            OracleKeyStore oks = OracleKeyStore.create();
            oks.engineLoad(is, new String(password).toCharArray() );
            
            // load the hashtable with all respective ASN.1 DER Object Identifiers (of the PKCS#12 wallet) into Enum
            Enumeration<String> keys = oks._extraProcessor.data.keys();
            
            // create multidim String array to split Oracle ASO keys from Oracle DB Credentials
            String[][] conIDs = new String[ oks._extraProcessor.data.size() ][3];
                    
            // regex pattern to split the content of the DER sequence
            Pattern p = Pattern.compile("oracle\\.security\\.client\\.(username|password|connect_string)([0-9]+)");
                    
            // loop thru the Enum hashtable
            while ( keys.hasMoreElements() ) {
                String key=keys.nextElement();
                String value=oks._extraProcessor.data.get(key);
     
                // check if the current element contains Oracle DB Credentials
                if ( key.matches("oracle.security.client(.*)") ) {
                    int i = 3;
                    Matcher m = p.matcher(key);
                    boolean b = m.matches();
                            
                    // check if the regex pattern matches the key String      
                    if ( b ) {
                        // define the respective int index for String[][]
                        if ( m.group(1).equals("username") )
                            i = 0;
                        else if (  m.group(1).equals("password") )
                            i = 1;
                        else if (  m.group(1).equals("connect_string") )
                            i = 2;   
                         
                        int j = Integer.parseInt( m.group(2) );
                        // to output the Oracle DB Credentials separately, they will be stored in the multidim String array
                        conIDs[j][i] = value;  
                    } else {
                         System.err.println("No regex match: " + key );
                    }
                // otherwise display the key and value (e.g. the Oracle ASO keys)
                } else {
                    System.out.println("key=" + key );
                    System.out.println("value=" + toHex(Base64.decode(value)) );
                }
            }

            System.out.println( "----------------------------------------------" );
            
            // loop thru the multidim String array and output the Oracle DB Credentials
            int j = 1;
            for ( int i = 0; i < conIDs.length; i++ ) {
                if( conIDs[i][0] != null ) {
                  System.out.println( "Credential #" + j + ": " + conIDs[i][0] + "/" + conIDs[i][1] + "@" + conIDs[i][2] );
                  j++;
                }
            }
        } catch (Exception e) {
            System.err.println( e.getMessage() );
        }            
    }
    
    // check if the password works
    private boolean checkWallet(byte[] password) 
    {
        InputStream is = new ByteArrayInputStream( walletP12 );        
        try {
            OracleKeyStore oks = OracleKeyStore.create();
            oks.engineLoad(is, new String(password).toCharArray() );
            return true;
        } catch (Exception e) {
			System.err.println( e.getMessage() );
            return false;
        }
    }
    
    // extract the SSO header from byte[] file data
    private String getSSOheader()
    { 
        if ( walletSSO != null ) {
            int hLen = 77;
            byte[] temp = new byte[hLen];
            System.arraycopy( walletSSO, 0, temp, 0, hLen);
            String header = new String( temp );
            
            if ( header.length() != 77 )
                System.err.println( "Header is not 77 chars long" );
                
            return header;
        }
        throw new NullPointerException("Wallet isn't loaded");
    }
    
    // extract the version from the first bytes of the SSO header
    private int getSSOVersion()
        throws NullPointerException
    { 
        if ( walletSSOheader != null ) {
            String version = toHex( walletSSOheader.substring(2, 11) ) ;
			
            if ( version.matches("4e360005000") ) {	// 10g wallet
                return 1;
            }
            else if ( version.matches("4e3(6|8)0006000") ) { // 11g wallet
                // check for "local" SSO wallet
                if ( version.equals("4e380006000") )
                    localSSO = true;
                return 2;
            } 
            else // unknown wallet version
                return 0;
        }
        throw new NullPointerException("Wallet isn't loaded");
    }
    
    // extract the key for the encrypted p12 password
    private byte[] getSSOkey()
        throws NullPointerException
    {
        if ( walletSSOheader != null ) {
            return hexStringToByteArray( walletSSOheader.substring(13, 29) );
        }
        throw new NullPointerException("Wallet isn't loaded");
    }
    
    // extract the encrypted p12 password
    private byte[] getSSOsecret()
        throws NullPointerException
    {
        if ( walletSSOheader != null ) {
            return hexStringToByteArray( walletSSOheader.substring(29, 77) );
        }
        throw new NullPointerException("Wallet isn't loaded");
    }
    
    // decrypting the PKCS#12 password (DES -> CBC -> PKCS7 padding)
    private byte[] decryptP12pwd(byte[] key, byte[] encPwd)
    {
        // define decryption key
        KeyParameter keyParam =  new KeyParameter( key );
        
        // define the cipher for decryption (DES, CBC and PKCS7 padding)
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new DESEngine()), new PKCS7Padding());

        cipher.init( false, keyParam );
        // get the original length of the password
        int    size = cipher.getOutputSize( encPwd.length );
        byte[] result = new byte[ size ];
        // decrypting...
        int    len = cipher.processBytes( encPwd, 0, encPwd.length, result, 0 );
        try {
            // process the last block of the buffer
            len += cipher.doFinal( result, len );
        }
        catch (InvalidCipherTextException e)
        {
            System.err.println( e.getMessage() );
        }
        
        // if the decrypted password is smaller than expected, create a correctly sized byte[]
        if( len < size ) {
            byte[] buffer = new byte[ len ];
            System.arraycopy(result, 0, buffer, 0, len );
            result = buffer;
        }
        return result;
    }
    
    // deobfuscation of the P12 password in LSSO wallets
    private byte[] deobLSSOpassword(byte[] password, String username, String hostname)
    {
        // get username and hostname from the current system if they are not specified over program arguments
        if ( username == null )
            username = System.getProperty("user.name");
        if ( hostname == null ) {
            try  {
                InetAddress net = InetAddress.getLocalHost();
                hostname = net.getHostName();
            } catch (UnknownHostException localUnknownHostException) {
                hostname = "oracle";
            }
        }
        
        // only first part of the hostname is used
        String[] s = null;
        if ( (s = hostname.split("\\.")).length > 1) 
            hostname = s[0];
                
        byte[] LSSOsecret = (hostname + username).getBytes();
        // calculate HMAC SHA1 
        //      (key = hostname + username; message = password)
        byte[] key = getMAC("HmacSHA1", LSSOsecret, password);
        
        // some deobfuscation required
        byte[] buf = new byte[16];
        for (int i = 0; i < buf.length; i++) 
            buf[i] = (byte)( key[i] + ((key[i] < 0) ? 129 : 1) );
           
        return buf;  
    }
    
    // calculate and return mac
    private byte[] getMAC (String algorithm, byte[] key, byte[] message) 
    {
        byte[] result = null;
        try {   
            // define raw secret key
            SecretKeySpec sKey = new SecretKeySpec(key, algorithm);
            // generate mac instance for the specific algorithm
            Mac m = Mac.getInstance(algorithm);
            // initialize the mac instance with sKey
            m.init(sKey);
            // calculate the mac for message
            result = m.doFinal(message);
        } catch (GeneralSecurityException e) {
            System.err.println( e.getMessage() ); 
        }
        return result;
    }

    // convert byte[] to hex string
    private String toHex(byte[] b) 
    {
        String result = "";
        for (int i=0; i < b.length; i++) {
        result +=
              Integer.toString( ( b[i] & 0xff ) + 0x100, 16).substring( 1 );
        }
        return result;
    }
    
    // convert String to hex string
    public String toHex(String s) 
    {
        char[] chars = s.toCharArray();
        StringBuffer strBuffer = new StringBuffer();
        for (int i = 0; i < chars.length; i++) {
            strBuffer.append(Integer.toHexString((int) chars[i]));
        }
        return strBuffer.toString();
    } 
   
    // convert hex string to bytes
    // http://stackoverflow.com/a/140861
    private static byte[] hexStringToByteArray(String s) 
    {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                            + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    // returns the content of a file as byte[]
    private byte[] readFileIntoByteArray(String filePath)
        throws java.io.IOException
    {
        File f= new File(filePath);
        FileInputStream fis = new FileInputStream( f );
        byte[] data = new byte[ (int)f.length() ];
        fis.read(data);
        
        return data;
    }

} // class ssoDecryptor