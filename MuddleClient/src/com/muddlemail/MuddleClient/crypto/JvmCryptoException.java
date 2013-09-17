package com.muddlemail.MuddleClient.crypto;

public class JvmCryptoException extends Exception {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1495237417678423468L;
	private static final String ERROR_MSG = 
			"Your JVM's Security Providers are not compliant with Muddle-Mail.  Please read the JVM requirements.";
	
	public JvmCryptoException(Throwable exception) {
		super(ERROR_MSG, exception);
	}
}
