/*
 * Session.java
 * 
 * Session object holds Principal ID [handle] and Attributes.
 * A random ID is used as the object key in the Cache and
 * is returned to the Browser as a Cookie value. 
 *
 * Recovery Context: No exceptions expected or generated.
 * 
 * --------------------
 * Copyright 2002, 2004 
 * University Corporation for Advanced Internet Development, Inc. 
 * All rights reserved
 * [Thats all we have to say to protect ourselves]
 * Your permission to use this code is governed by "The Shibboleth License".
 * A copy may be found at http://shibboleth.internet2.edu/license.html
 * [Nothing in copyright law requires license text in every file.]
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
	
	Session(String key) {
		// Should only be created by SessionManager
	    this.key=key;
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
	private long lifetime;
	public long getLifetime() {
		return lifetime;
	}
	public void setLifetime(long lifetime) {
		this.lifetime = lifetime;
	}
	
	private long timeout;
	public long getTimeout() {
		return timeout;
	}
	public void setTimeout(long timeout) {
		this.timeout = timeout;
	}
	
    // private persisted variable
	private long timestamp = System.currentTimeMillis();
	
	
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
