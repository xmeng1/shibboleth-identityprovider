/*
 * Session.java
 * 
 * Session object holds Principal ID [handle] and Attributes.
 * A generated UUID is used as the object key in the Cache and
 * is returned to the Browser as a Cookie value. 
 *
 * External Dependencies: jug.jar to generate UUID
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

import org.doomdark.uuid.UUIDGenerator;
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
	
	Session() {
		// Should only be created by SessionManager.newSession()
	}
	
	// Properties
	private String key = generateKey();
	private String applicationId = null;
	private String ipaddr = null;
	private String entityId = null; // a.k.a providerId
	public String getEntityId() {
		return entityId;
	}
	public void setEntityId(String entityId) {
		this.entityId = entityId;
	}
	private long lifetime;
	private long timeout;
	
	public long getLifetime() {
		return lifetime;
	}
	public void setLifetime(long lifetime) {
		this.lifetime = lifetime;
	}
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
	private SAMLAuthenticationStatement authenticationStatement=null;
	
	// Stuff saved from the Attribute Query
	private SAMLResponse attributeResponse = null;
	/*
	 * Internal key generation logic. Designed not to fail.
	 * This is not the place to signal configuration problems.
	 * Sanity check the CLASSPATH long before you call down to here.
	 */
	private static long terriblefallback = new java.util.Random().nextLong();
	private static String generateKey() {
		try {
			// Note: performance can be improved by creating a synchonized
			// static UUIDGenerator preinitialized. 
			return UUIDGenerator.getInstance().generateTimeBasedUUID().toString();
		} catch (Throwable t) {
			// Probably the jug.jar file is missing in WEB-INF/lib
			// Generate a unique but easy to guess integer.
			return Long.toString(terriblefallback++);
		}
	}

	/**
	 * @return Returns the ipaddr.
	 */
	public String getIpaddr() {
		return ipaddr;
	}
	/**
	 * @param ipaddr The ipaddr to set.
	 */
	public void setIpaddr(String ipaddr) {
		this.ipaddr = ipaddr;
	}
	/**
	 * @return Returns the applicationId.
	 */
	public String getApplicationId() {
		return applicationId;
	}
	/**
	 * @param applicationId The applicationId to set.
	 */
	public void setApplicationId(String applicationId) {
		this.applicationId = applicationId;
	}
	/**
	 * @return Returns the key.
	 */
	public String getKey() {
		return key;
	}
	public void renew(){
		timestamp = System.currentTimeMillis();
	}
	

	public SAMLAssertion getAuthenticationAssertion() {
		return authenticationAssertion;
	}
	public void setAuthenticationAssertion(SAMLAssertion authentication) {
		this.authenticationAssertion = authentication;
	}
	public SAMLAuthenticationStatement getAuthenticationStatement() {
		return authenticationStatement;
	}
	public void setAuthenticationStatement(
			SAMLAuthenticationStatement authenticationStatement) {
		this.authenticationStatement = authenticationStatement;
	}
	public SAMLResponse getAttributeResponse() {
		return attributeResponse;
	}
	public void setAttributeResponse(SAMLResponse attributeResponse) {
		this.attributeResponse = attributeResponse;
	}
}
