package com.muddlemail.MuddleClient.http;

public class FailedPostException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = -2840503508285249478L;
	
	public FailedPostException(String message, Throwable cause) {
		super(message, cause);
	}
}
