package com.muddlemail.MuddleClient.crypto;

public class FailedToDecryptException extends Exception {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -5607587216669063574L;

	public FailedToDecryptException(Throwable exception) {
		super(exception);
	}
}
