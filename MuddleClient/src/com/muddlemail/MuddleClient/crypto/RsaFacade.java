package com.muddlemail.MuddleClient.crypto;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.io.CipherInputStream;

public class RsaFacade {
	public static final int RSA_KEY_SIZE = 4096;
	public static final String CIPHER_NAME_SHORT = "RSA";
	public static final String CIPHER_NAME_LONG = "RSA/ECB/PKCS1Padding";
	
	
	
	public RsaFacade() {
		
	}
	
	
	public static AsymmetricKeyPair genKeyPair() throws JvmCryptoException {
		KeyPairGenerator kpg = null;
		KeyPair kp = null;
		
        try {
            kpg = KeyPairGenerator.getInstance(CIPHER_NAME_SHORT, "BC");
            kpg.initialize(RSA_KEY_SIZE);
            kp = kpg.genKeyPair();
        } catch (NoSuchAlgorithmException | 
        		 NoSuchProviderException  e) 
        {
            throw new JvmCryptoException(e);
        }

        return new AsymmetricKeyPair(kp.getPublic().getEncoded(), kp.getPrivate().getEncoded());
	}
	
	
	/**
	 * 
	 * @param dataPlain
	 * @param keyPublic
	 * @return
	 * @throws FailedToEncryptException
	 */
	public static byte[] encryptDataWithPublic(
		byte[] dataPlain, 
		byte[] keyPublic) 
	throws FailedToEncryptException
	{
		
		PublicKey key = null;
		try {
			key = KeyFactory
					.getInstance(CIPHER_NAME_SHORT, "BC")
					.generatePublic(new X509EncodedKeySpec(keyPublic));	
		} 
		catch (InvalidKeySpecException | NoSuchAlgorithmException
				| NoSuchProviderException e) {
			throw new FailedToEncryptException(e);
		}


		return encryptData(dataPlain, key);
	}
	
	
	
	/**
	 * 
	 * @param dataPlain
	 * @param key
	 * @return
	 * @throws FailedToEncryptException 
	 */
	protected static byte[] encryptData(byte[] dataPlain, Key key) 
    throws FailedToEncryptException
    {
		byte[] dataCipher = null;

		try {
			System.out.println(key.getFormat());
			Cipher cipher = Cipher.getInstance(CIPHER_NAME_LONG, "BC");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			dataCipher = cipher.doFinal(dataPlain);
		} 
		catch (NoSuchAlgorithmException    | 
				 NoSuchProviderException   | 
				 NoSuchPaddingException    | 
				 InvalidKeyException       | 
				 IllegalBlockSizeException | 
				 BadPaddingException       e) 
		{
			throw new FailedToEncryptException(e);
		}
		
		return dataCipher;
	}
	
	
	public static byte[] decryptData(byte[] dataCipher, byte[] key){
		return null;
	}
}
