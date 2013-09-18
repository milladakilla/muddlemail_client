package com.muddlemail.MuddleClient.crypto;

public class FailedToEncryptException extends Exception {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -2976420054147410560L;

	public FailedToEncryptException(Throwable exception) {
		super(exception);
	}
}
