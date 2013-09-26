package com.muddlemail.MuddleClient.crypto;

import org.bouncycastle.util.encoders.Base64;

public class AsymmetricKeyPair {
	private byte[] keyPrivate;
	private byte[] keyPublic;
	
	/**
	 * 
	 * @param keyPublic
	 * @param keyPrivate
	 */
	public AsymmetricKeyPair(byte[] keyPublic, byte[] keyPrivate) {
		this.keyPublic = keyPublic;
		this.keyPrivate = keyPrivate;
	}
	
	/**
	 * 
	 * @return
	 */
	public byte[] getPrivateKey() {
		return keyPrivate;
	}
	
	/**
	 * 
	 * @return
	 */
	public byte[] getPublicKey() {
		return keyPublic;
	}
	
	/**
	 * 
	 * @return
	 */
	public String getBase64PrivateKey() {
		return new String(Base64.encode(getPrivateKey()));
	}
	
	/**
	 * 
	 * @return
	 */
	public String getBase64PublicKey() {
		return new String(Base64.encode(getPublicKey()));
	}
	
	
}
