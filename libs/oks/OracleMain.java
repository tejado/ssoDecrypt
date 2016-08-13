package oks;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Enumeration;
import org.bouncycastle.util.encoders.Base64;


public class OracleMain {
	
	public static void main(String args[]) {
		try {
			OracleKeyStore oks=OracleKeyStore.create();
			if(args.length != 2){
				System.out.println("Usage:\nOrcleMain walletfile walletpassword\n");
				return;
			}
			
			String fileName=args[0];
			char[] password=args[1].toCharArray();
			InputStream is=new FileInputStream(fileName);
			
			oks.engineLoad(is, password);
			
	        Enumeration<String> keys=oks._extraProcessor.data.keys();
	        while (keys.hasMoreElements()) {
	        	String key=keys.nextElement();
	        	String value=oks._extraProcessor.data.get(key);
	        	System.out.println("key="+key);
	        	System.out.println("value="+getHex(Base64.decode(value)));
	        }

			
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	static final String HEXES = "0123456789ABCDEF";
  	public static String getHex( byte [] raw ) {
    		if ( raw == null ) {
      		return null;
   	}
   	final StringBuilder hex = new StringBuilder( 2 * raw.length );
    	for ( final byte b : raw ) {
      	hex.append(HEXES.charAt((b & 0xF0) >> 4))
        	 .append(HEXES.charAt((b & 0x0F)));
    	}
   	 return hex.toString();
  	}
	

}
