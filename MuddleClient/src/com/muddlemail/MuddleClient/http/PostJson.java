package com.muddlemail.MuddleClient.http;

import java.io.IOException;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicHeader;
import org.apache.http.util.EntityUtils;

import com.google.gson.Gson;

/**
 * 
 * @author matt
 *
 */
public class PostJson {
///////////////////////////////////////////////////////////////////////////////
// Class Variables ////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
	protected HttpClient httpClient = new DefaultHttpClient();
	protected HttpPost httpPost = null;
	
	final static protected Header USER_AGENT = new BasicHeader("user-agent", "muddlemail");
	
	final static protected ContentType CONTENT_TYPE_JSON = 
			ContentType.create("application/json");
	
	protected StringEntity jsonEntity;
	
///////////////////////////////////////////////////////////////////////////////
// Constructors ///////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
	/**
	 * 
	 * @param url
	 * @param jsonData
	 */
	public PostJson (String url, Object obj) {
		Gson gson = new Gson();
		String jsonData = gson.toJson(obj);
		jsonEntity = new StringEntity(jsonData, CONTENT_TYPE_JSON);
		
		httpPost = new HttpPost(url);
		httpPost.setHeader(USER_AGENT);
		httpPost.setEntity(jsonEntity);
	}

///////////////////////////////////////////////////////////////////////////////
// Methods ////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
	/**
	 * 
	 * @return
	 * @throws FailedPostException
	 */
	public JsonResponse executePost() throws FailedPostException {
		HttpResponse resp = null;
		JsonResponse jsonResp = null;
		
		try {
			resp = httpClient.execute(httpPost);
			jsonResp = new JsonResponse(
					EntityUtils.toString(resp.getEntity()),
					resp.getStatusLine().getStatusCode());
			
		} 
		catch (ClientProtocolException e) {
			throw new FailedPostException(e.getMessage(), e.getCause());
			
		} 
		catch (IOException e) {
			throw new FailedPostException(e.getMessage(), e.getCause());
			
		} 
		finally {
		    httpPost.releaseConnection();
		}
		
		return jsonResp;
	}
}