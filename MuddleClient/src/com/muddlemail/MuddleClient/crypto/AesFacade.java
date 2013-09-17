package com.muddlemail.MuddleClient.crypto;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;

import javax.crypto.KeyGenerator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AesFacade {
	public static final String CIPHER_NAME_SHORT = "AES";
	public static final int AES_KEY_SIZE = 256;
	public static final String PROVIDER_BC = "BC";
	public static final String PROVIDER_SUN = "Sun";

	public AesFacade() {

	}

	/**
	 * Create a muddle-mail compliant AES-256 key.
	 * 
	 * @return keyAes
	 * @throws JvmCryptoException 
	 */
	public Key genKey() throws JvmCryptoException {
		KeyGenerator generator;
		Key keyAes = null;

		try {
			generator = KeyGenerator
					.getInstance(CIPHER_NAME_SHORT, PROVIDER_BC);

			generator.init(AES_KEY_SIZE);
			keyAes = generator.generateKey();

		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new JvmCryptoException(e);
		}

		return keyAes;
	}

	/**
	 * 
	 * @param plainData
	 * @return
	 */
	public byte[] encryptData(byte[] dataPlain, Key keyAes) {

		return null;
	}
}
