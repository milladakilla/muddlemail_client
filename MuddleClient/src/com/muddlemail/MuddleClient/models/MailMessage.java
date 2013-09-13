package com.muddlemail.MuddleClient.models;

public class MailMessage {
	public String aesCbcData;
	public String aesCbcIv;
	public String aesCbcPassword;
	
	public MailMessage (String aesCbcData, String aesCbcIv, String aesCbcPassword) {
		this.aesCbcData = aesCbcData;
		this.aesCbcIv = aesCbcIv;
		this.aesCbcPassword = aesCbcPassword;
	}
	
	
}
