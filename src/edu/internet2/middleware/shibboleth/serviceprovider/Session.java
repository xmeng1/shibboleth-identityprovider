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
 * Each session generates its own random key.<br>
 * The collection of Session objects may be checkpointed to disk using
 * any attractive persistence framework, Object Relational mapping, 
 * or, hell, just serialize the objects to a flat file if you like.
 *
 *  @author Howard Gilbert
 */
public class Session implements Serializable {
    private long maxSessionLife;
    private long unusedSessionTimeout;
    private long defaultAttributeLifetime;
	
    /**
     * Create a Session object. Only used by the Session Manager, so it has package scope.
     * 
     * @param key Random generated sessionId string
     * @param maxSessionLife Maximum time this Session can remain valid
     * @param unusedSessionTimeout Discard an unused Session
     * @param defaultAttributeLifetime Default attribute validity time
     */
	Session(String key, 
            long maxSessionLife, 
            long unusedSessionTimeout, 
            long defaultAttributeLifetime) {
		if (key==null)
			throw new IllegalArgumentException();
	    this.key=key;
	    this.lastused = System.currentTimeMillis();
        this.created = this.lastused;
        this.maxSessionLife=maxSessionLife*1000;
        this.unusedSessionTimeout=unusedSessionTimeout*1000;
        this.defaultAttributeLifetime=defaultAttributeLifetime*1000;
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
	
	private long lastused = 0;
    private long created = 0;
	
	public boolean isExpired() {
		long now = System.currentTimeMillis();
		if (maxSessionLife>0 && 
                created+maxSessionLife<now)
			return true;
		if (unusedSessionTimeout>0 && 
                lastused+unusedSessionTimeout<now)
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

	/**
     * Called by Session Manager when the Session is used. Reset the 
     * unused timer.
	 */
	void renew(){
		lastused = System.currentTimeMillis();
	}
    
    public long getDefaultAttributeLifetime() {
        return defaultAttributeLifetime;
    }

    public void setDefaultAttributeLifetime(long defaultAttributeLifetime) {
        this.defaultAttributeLifetime = defaultAttributeLifetime*1000;
    }

    public long getMaxSessionLife() {
        return maxSessionLife;
    }

    public void setMaxSessionLife(long maxSessionLife) {
        this.maxSessionLife = maxSessionLife*1000;
    }

    public long getUnusedSessionTimeout() {
        return unusedSessionTimeout;
    }

    public void setUnusedSessionTimeout(long unusedSessionTimeout) {
        this.unusedSessionTimeout = unusedSessionTimeout*1000;
    }
	

}
