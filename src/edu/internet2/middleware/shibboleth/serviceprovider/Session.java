/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Session.java
 * 
 * Session object holds Principal ID [handle] and Attributes.
 * A random ID is used as the object key in the Cache and
 * is returned to the Browser as a Cookie value. 
 *
 * Recovery Context: No exceptions expected or generated.
 */
package edu.internet2.middleware.shibboleth.serviceprovider;

import java.io.Serializable;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAuthenticationStatement;
import org.opensaml.SAMLResponse;

/**
 * Session object holds Authentication and Attribute Assertions for one
 * remote Browser/User.<br>
 * Each session generates its own UUID key.<br>
 * The collection of Session objects may be checkpointed to disk using
 * any attractive persistence framework, Object Relational mapping, 
 * or, hell, just serialize the objects to a flat file if you like.
 *
 *  @author Howard Gilbert
 */
public class Session implements Serializable {
	
	// Default values from Shibboleth documentation
	private static final int DEFAULTTIMEOUT = 1800000;
	public static final int DEFAULTLIFETIME = 3600000;
	
	Session(String key) {
		// Should only be created by SessionManager
		if (key==null)
			throw new IllegalArgumentException();
	    this.key=key;
	    this.timestamp = System.currentTimeMillis();
	}
	
	/**
	 * For testing, create a Session that may already be timed out.
	 */
	Session(String key, long timestamp) {
	    this.key=key;
	    this.timestamp = timestamp;
	}
	
	// Properties
	
	private String key;
	public String getKey() {
		return key;
	}
	
	private String applicationId = null;
	public String getApplicationId() {
		return applicationId;
	}
	public void setApplicationId(String applicationId) {
		this.applicationId = applicationId;
	}
	
	private String ipaddr = null;
	public String getIpaddr() {
		return ipaddr;
	}
	public void setIpaddr(String ipaddr) {
		this.ipaddr = ipaddr;
	}
	
	private String entityId = null; // a.k.a providerId
	public String getEntityId() {
		return entityId;
	}
	public void setEntityId(String entityId) {
		this.entityId = entityId;
	}
	
	private long lifetime = DEFAULTLIFETIME;
	public long getLifetime() {
		return lifetime;
	}
	public void setLifetime(long lifetime) {
		this.lifetime = lifetime;
	}
	
	private long timeout=DEFAULTTIMEOUT;
	public long getTimeout() {
		return timeout;
	}
	public void setTimeout(long timeout) {
		this.timeout = timeout;
	}
	
    // private persisted variable
	private long timestamp = 0;
	
	public boolean isExpired() {
		long now = System.currentTimeMillis();
		if (lifetime>0 && timestamp+lifetime<now)
			return true;
		if (timeout>0 && timestamp+timeout<now)
			return true;
		return false;
	}
	
	
	// Stuff saved from the POST
	private SAMLAssertion authenticationAssertion = null;
	public SAMLAssertion getAuthenticationAssertion() {
		return authenticationAssertion;
	}
	public void setAuthenticationAssertion(SAMLAssertion authentication) {
		this.authenticationAssertion = authentication;
	}
	
	private SAMLAuthenticationStatement authenticationStatement=null;
	public SAMLAuthenticationStatement getAuthenticationStatement() {
		return authenticationStatement;
	}
	public void setAuthenticationStatement(
			SAMLAuthenticationStatement authenticationStatement) {
		this.authenticationStatement = authenticationStatement;
	}
	
	// Stuff saved from the Attribute Query
	private SAMLResponse attributeResponse = null;
	public SAMLResponse getAttributeResponse() {
		return attributeResponse;
	}
	public void setAttributeResponse(SAMLResponse attributeResponse) {
		this.attributeResponse = attributeResponse;
	}

	
	public void renew(){
		timestamp = System.currentTimeMillis();
	}
	

}
