package com.muddlemail.MuddleClient.main;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import com.muddlemail.MuddleClient.crypto.AesCbcData;
import com.muddlemail.MuddleClient.crypto.AesFacade;
import com.muddlemail.MuddleClient.crypto.AsymmetricKeyPair;
import com.muddlemail.MuddleClient.crypto.FailedToDecryptException;
import com.muddlemail.MuddleClient.crypto.FailedToEncryptException;
import com.muddlemail.MuddleClient.crypto.JvmCryptoException;
import com.muddlemail.MuddleClient.crypto.RsaFacade;
import com.muddlemail.MuddleClient.gui.MainWindow;

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
			
			//testAes();
			testRsa();
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void testAes() 
    throws JvmCryptoException, 
           FailedToEncryptException, 
           FailedToDecryptException 
    {
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
	}

	public static void testRsa() throws JvmCryptoException {
		String message = "HELLO WORLD";
	
		AsymmetricKeyPair kp = RsaFacade.genKeyPair();
		
		System.out.println( kp.getBase64PublicKey() );
		System.out.println( kp.getBase64PrivateKey() );
		
		byte[] cipherData = null;
		
		try {
			cipherData = RsaFacade.encryptDataWithPublic(message.getBytes(), kp.getPublicKey());
		} catch (FailedToEncryptException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		System.out.println("Cipher Data:" + new String(Base64.encode(cipherData)) );
		System.out.println("Cipher length: " + cipherData.length);
	}
}
