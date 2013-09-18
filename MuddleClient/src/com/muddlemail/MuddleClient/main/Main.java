package com.muddlemail.MuddleClient.main;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import com.muddlemail.MuddleClient.crypto.AesCbcData;
import com.muddlemail.MuddleClient.crypto.AesFacade;

public class Main {

	/**
	 * Launch the application.
	 * @param args
	 */
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		
		try {
			//MainWindow window = new MainWindow();
			//window.open();
			
			
					
		    String message = "HELLO WORLD";
			byte[] dataPlain = message.getBytes();
			AesCbcData dataCipher;
			byte[] dataDecrypted;
		
			byte[] keyAes = AesFacade.genKey();
			
			System.out.println("Key        : " + new String(Base64.encode(keyAes)));
			System.out.println("Key Size   : " + keyAes.length * 8 + "bits");
			
			dataCipher = AesFacade.encryptData(dataPlain, keyAes);
			System.out.println( "Cipher Data: " + new String(Base64.encode(dataCipher.getDataCipher())) );
			System.out.println( "Cipher size: " + (dataCipher.getDataCipher().length * 8) / 128.0 + " aes-blocks" );
			
			
			System.out.println("IV         : " + new String(Base64.encode(dataCipher.getIv())));
			
			dataDecrypted = AesFacade.decryptData(dataCipher, keyAes);
			System.out.println("Decrypted  : " + new String(dataDecrypted));
			
			
			
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
