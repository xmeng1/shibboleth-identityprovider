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
 * remote Browser/User for one ApplicationId.<br>
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
	    this.sessionId=key;
	    this.lastused = System.currentTimeMillis();
        this.created = this.lastused;
        this.maxSessionLife=maxSessionLife*1000;
        this.unusedSessionTimeout=unusedSessionTimeout*1000;
        this.defaultAttributeLifetime=defaultAttributeLifetime*1000;
	}
	
	// Properties
	
    /*
     * The large random SessionId string generated for this Session.
     * It is used as the key of the SessionManager cache, so this 
     * field is only actually needed if serialized/persisted Sessions
     * need to be reloaded after a crash.
     */
	private String sessionId;
	public String getSessionId() {
		return sessionId;
	}
	
    /*
     * The ApplicationId associated with this Session. A remote User
     * may have different Sessions with different ApplicationIds that
     * associate to different IdPs or Attributre Release policies.
     */
	private String applicationId = null;
	public String getApplicationId() {
		return applicationId;
	}
	public void setApplicationId(String applicationId) {
		this.applicationId = applicationId;
	}
	
    /*
     * Remote IP address of Browser. Might be used as extra validity check.
     */
	private String ipaddr = null;
	public String getIpaddr() {
		return ipaddr;
	}
	public void setIpaddr(String ipaddr) {
		this.ipaddr = ipaddr;
	}
	
    /*
     * IdP entity
     */
	private String entityId = null; 
	public String getEntityId() {
		return entityId;
	}
	public void setEntityId(String entityId) {
		this.entityId = entityId;
	}
	
	private long lastused = 0;
    private long created = 0;
	
    /**
     * Determines if the Session has timed out.
     * @return true if timed out
     */
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
    
    /**
     * Is this an empty Session object reserved by an RM that has not yet
     * received Assertions.
     * @return true or false
     */
    public boolean isInitialized() {
        return (null!=getAuthenticationStatement());
    }
	
	
	// Stuff saved from the POST
    
    /*
     * The SAML Authentication Assertion from the POST or Artifact
     */
	private SAMLAssertion authenticationAssertion = null;
	public SAMLAssertion getAuthenticationAssertion() {
		return authenticationAssertion;
	}
	public void setAuthenticationAssertion(SAMLAssertion authentication) {
		this.authenticationAssertion = authentication;
	}
	
    /*
     * The saved Authentication Statement containing the Assertion 
     * referenced above. There are extra fields at this level that
     * are useful to build the Attribute Query.
     */
	private SAMLAuthenticationStatement authenticationStatement=null;
	public SAMLAuthenticationStatement getAuthenticationStatement() {
		return authenticationStatement;
	}
	public void setAuthenticationStatement(
			SAMLAuthenticationStatement authenticationStatement) {
		this.authenticationStatement = authenticationStatement;
	}
	
    /*
     * The SAMLResponse containing the Attribute Assertions. Note that
     * in Attribute Push or Artifact situations, this Response will
     * also contain the Authentication elements separately referenced
     * above. Otherwise, this Response will have been returned from
     * a Query.
     */
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
    
    /**
     * Return the default lifetime of an Attribute Assertion if the
     * Assertion itself doesn't specify the limit.
     */
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
    
    /*
     * The FormalURL references the RM itself instead of any 
     * individual resource.
     */
    private String formalURL;
    public String getFormalURL() {
        return formalURL;
    }
    public void setFormalURL(String formalURL) {
        this.formalURL = formalURL;
    }
    
    /*
     * The SavedTarget URL is meaningful only in an uninitialized but
     * preallocate Session object. It holds the original Resource
     * URL to which the Browser will be redirected after the
     * Session is actually established. This frees the TARGET=
     * sent to the WAYF to be the key of this object rather than
     * a real URL.
     */
    private String savedTargetURL;
    public String getSavedTargetURL() {
        return savedTargetURL;
    }
    public void setSavedTargetURL(String savedResourceURL) {
        this.savedTargetURL = savedResourceURL;
    }
	

}
