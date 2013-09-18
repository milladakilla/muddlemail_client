package com.muddlemail.MuddleClient.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesFacade {
	public static final String CIPHER_NAME_SHORT = "AES";
	public static final String CIPHER_NAME_LONG = "AES/CBC/PKCS7Padding";
	public static final String PROVIDER_BC = "BC";
	public static final String PROVIDER_SUN = "SUN";
	public static final int AES_KEY_SIZE = 256;

	public AesFacade() {

	}

	/**
	 * Create a muddle-mail compliant AES-256 key.
	 * 
	 * @return keyAes
	 * @throws JvmCryptoException
	 */
	public static byte[] genKey() throws JvmCryptoException {
		KeyGenerator generator;
		byte[] keyAes = null;

		try {
			generator = KeyGenerator
					.getInstance(CIPHER_NAME_SHORT, PROVIDER_BC);
			
			generator.init(AES_KEY_SIZE);
			keyAes = generator.generateKey().getEncoded();

		} catch (NoSuchAlgorithmException |
				 NoSuchProviderException  e) 
		{
			throw new JvmCryptoException(e);
		}

		return keyAes;
	}

	/**
	 * AES Encryption the Muddle-Mail way.  This is an in memory operation, so
	 * be careful with the input size.  This is not a streaming solution.
	 * 
	 * @param plain-data<br>aes-key
	 * @return AesCbcData - holds both the cipherData and the I.V.
	 * @throws FailedToEncryptException 
	 */
	public static AesCbcData encryptData(byte[] dataPlain, byte[] keyAes) throws FailedToEncryptException {
		Cipher cipherAes = null;
		byte[] dataCipher = null;

		try {
			SecretKeySpec skeySpec = new SecretKeySpec(keyAes, CIPHER_NAME_SHORT);
		
			cipherAes = Cipher.getInstance(CIPHER_NAME_LONG, PROVIDER_BC);
			cipherAes.init(Cipher.ENCRYPT_MODE, skeySpec);
			dataCipher = cipherAes.doFinal(dataPlain);
			
		} catch (NoSuchAlgorithmException  | 
				 NoSuchPaddingException    |
				 InvalidKeyException       | 
				 NoSuchProviderException   | 
				 IllegalBlockSizeException | 
				 BadPaddingException       e) 
		{
			throw new FailedToEncryptException(e);
		}
		
		return new AesCbcData(dataCipher, cipherAes.getIV());
	}
	
	/**
	 * AES Decryption the Muddle-Mail way.  This is an in memory operation, so
	 * be careful with the input size.  This is not a streaming solution.
	 * 
	 * @param cipher-data<br>aes-key
	 * @return plain-data
	 * @throws FailedToDecryptException 
	 */
	public static byte[] decryptData(AesCbcData dataCipher, byte[] keyAes) throws FailedToDecryptException {
		Cipher          cipher;
		byte[]          dataPlain = null;
		IvParameterSpec iv = new IvParameterSpec(dataCipher.getIv());
		
		try {
			cipher = Cipher.getInstance(CIPHER_NAME_LONG, PROVIDER_BC);
			SecretKeySpec skeySpec = new SecretKeySpec(keyAes, CIPHER_NAME_SHORT);
			
			cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
			dataPlain = cipher.doFinal(dataCipher.getDataCipher());
		} catch (NoSuchAlgorithmException           |
                 NoSuchProviderException            | 
                 NoSuchPaddingException             |
                 InvalidKeyException                |
                 InvalidAlgorithmParameterException |
                 IllegalBlockSizeException          |
                 BadPaddingException                e) 
		{
			throw new FailedToDecryptException(e);
		}
		
		return dataPlain;
	}
}
