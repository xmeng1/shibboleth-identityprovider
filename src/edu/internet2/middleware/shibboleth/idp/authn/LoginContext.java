/*
 * Copyright [2006] [University Corporation for Advanced Internet Development, Inc.]
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

package edu.internet2.middleware.shibboleth.idp.authn;


import java.util.Map;
import javolution.util.FastMap;

import org.joda.time.DateTime;


/**
 * Login context created by a profile handler and interpreted
 * by the authentication package.
 * 
 * Two properties are tracked by default:
 * 
 * <code>forceAuth</code> - Should user authentiation be forced.
 * <code>passiveAuth</code> - Should user authentication not control the UI.
 * 
 * A Map&lt;String, Object&gt; is provided to store other properties.
 * Alternatively, a profile handler may create a subclass of LoginContext with
 * extra fields.
 *
 * LoginContexts should be created by a profile handler when authentication is needed.
 * Once control has returned to the profile handler, it should remove the LoginContext
 * from the HttpSession.
 *
 * The {@link AuthenticationManager} or an {@link AuthenticationHandler} should set the
 * {@link LoginContext#setAuthenticationAttempted()}, {@link LoginContext#setAuthnOK(boolean)},
 * {@link LoginContext#setAuthnFailure(String)} appropriately.
 *
 */
public class LoginContext {
    
    /** the key in a HttpSession where login contexts are stored */
    public static final String LOGIN_CONTEXT_KEY = "shib2.logincontext";
    
    
    /** Should user authentication be forced */
    private boolean forceAuth = false;
    
    /** Must authentication not interact with the UI */
    private boolean passiveAuth = false;
    
    /** a catch-all map for other properties */
    private Map<String, Object> propsMap = new FastMap<String, Object>();
    
    /** The ProfileHandler URL */
    private String profileHandlerURL;
    
    /** The AuthenticationManager's URL */
    private String authnManagerURL;
    
    /** has authentication been attempted yet */
    private boolean authnAttempted = false;
    
    /** The id of the authenticated user */ 
    private String userID;

    /** Did authentication succceed? */
    private boolean authenticationOK;
    
    /** Optional failure message  */
    private String authnFailureMessage;

    /** The instant of authentication */
    private DateTime authnInstant;
    
    /** The duration of authentication */
    private long authnDuration;
    
    /** The method used to authenticate the user */
    private String authnMethod;        
    
    /** The session id */
    private String sessionID;
    
    
    /** Creates a new instance of LoginContext */
    public LoginContext() {
    }
    
    
    /**
     * Creates a new instance of LoginContext
     *
     * @param forceAuth if the authentication manager must reauth the user.
     * @param passiveAuth if the authentication manager must not interact with the users UI. 
     */
    public LoginContext(boolean forceAuth, boolean passiveAuth) {
        
        this.forceAuth = forceAuth;
        this.passiveAuth = passiveAuth;
    }    
    
    
    /**
     * Returns if authentication must be forced.
     *
     * @return <code>true</code> if the authentication manager must reauth the user.
     */
    public boolean getForceAuth() {
        return this.forceAuth;
    }
    
    
    /**
     * Returns if authentication must be passive.
     * 
     * @return <code>true</code> if the authentication manager must not interact with the users UI.
     */
    public boolean getPassiveAuth() {
        return this.passiveAuth;
    }
    
    
    /**
     * Sets if authentication must be forced.
     *
     * @param forceAuth if the authentication manager must reauth the user.
     */
    public void setForceAuth(boolean forceAuth) {
        this.forceAuth = forceAuth;
    }
    
    
    /**
     * Sets if authentication must be passive.
     * 
     * @param passiveAuth if the authentication manager must not interact with the users UI.
     */
    public void setPassiveAuth(boolean passiveAuth) {
        this.passiveAuth = passiveAuth;
    }
    
    
    /**
     * Get an optional property object.
     * 
     * @param key The key in the properites Map.
     * 
     * @return The object, or <code>null</code> is no object exists for the key.
     */
    public Object getProperty(String key) {
        return this.propsMap.get(key);
    }
    
    
    /**
     * Sets an optional property object.
     * 
     * If an object is already associated with key, it will be overwritten.
     * 
     * @param key The key to set.
     * @param obj The object to associate with key.
     */
    public void setProperty(String key, final Object obj) {
        this.propsMap.put(key, obj);
    }
 
    
    /**
     * Sets if authentication succeeded.
     * 
     * @param authnOK if authentication succeeded;
     */
    public void setAuthnOK(boolean authnOK) {
        this.authenticationOK = authnOK;
    }
    
    
    /**
     * Returns if authentication succeeded.
     * 
     * @return <code>true</code> is the user was successfully authenticated.
     */
    public boolean getAuthnOK() {
        return this.authenticationOK;
    }
    
    
    /** Sets the optional authentication failure message.
     * 
     * @param failureMessage A description of why authN failed.
     */ 
    public void setAuthnFailureMessage(String failureMessage) {
        this.authnFailureMessage = failureMessage;
    }
    
    
    /**
     * Returns the optional authentication failure message.
     * 
     * @return The failure message, or <code>null</code> is none was set.
     */
    public String getAuthnFailureMessage() {
        return this.authnFailureMessage;
    }
    
    
    /**
     * Set if authentication has been attempted.
     *
     * This method should be called by an {@link AuthenticationHandler} 
     * while processing a request.
     */
    public void setAuthenticationAttempted() {
	this.authnAttempted = true;
    }
    
    
    /**
     * Returns if authentication has been attempted for this user.
     */
    public boolean getAuthenticationAttempted() {
	return this.authnAttempted;
    }
    
    
    /**
     * Sets the ID of the authenticated user.
     * 
     * @param userID The userid.
     */
    public void setUserID(String userID) {
        this.userID = userID;
    }
    
    
    /**
     * Returns the ID of the authenticated user.
     * 
     * @return the ID of the user, or <code>null</code> if authentication failed.
     */
    public String getUserID() {
        return this.userID;
    }
    
    
    /**
     * Gets the ProfileHandler URL.
     *
     * @return the URL of the profile handler that is invoking the Authentication Manager.
     */
    public String getProfileHandlerURL() {
	return this.profileHandlerURL;
    }
    
    
    /**
     * Sets the ProfileHandler URL.
     *
     * @param profileHandlerURL The URL of the profile handler that invoked the AuthenticationManager/
     */
    public void setProfileHandlerURL(String profileHandlerURL) {
	this.profileHandlerURL = profileHandlerURL;
    }
    
    
    /**
     * Gets the AuthenticationManager URL.
     *
     * @return the URL of the AuthenticationManager.
     */
    public String getAuthnManagerURL() {
	return this.authnManagerURL;
    }
    
    
    /**
     * Sets the AuthenticationManager's URL.
     *
     * @param authnManagerURL the URL of the AuthenticationManager.
     */
    public void setAuthnManagerURL(String authnManagerURL) {
	this.authnManagerURL = authnManagerURL;
    }
    
    
    /**
     * Gets the authentication instant.
     *
     * @return The instant of authentication, or <code>null</code> if none was set.
     */
    public DateTime getAuthenticationInstant() {
	    return this.authnInstant;
    }
    
    
    /**
     * Sets the authentication instant.
     *
     * @param authnInstant The instant of authentication.
     */
    public void setAuthenticationInstant(final DateTime authnInstant) {
	this.authnInstant = authnInstant;
    }
    
    
    /**
     * Gets the duration of authentication.
     *
     * @return The duration of authentication, or zero if none was set.
     */
    public long getAuthenticationDuration() {
	return this.authnDuration;
    }
    
    
    /**
     * Sets the duration of authentication.
     *
     * @param authnDuration The duration of authentication.
     */
    public void setAuthenticationDuration(long authnDuration) {
	this.authnDuration = authnDuration;
    }
    
    
    /**
     * Gets the method used to authenticate the user.
     *
     * @return The method used to authenticate the user.
     */
    public String getAuthenticationMethod() {
	return this.authnMethod;
    }
    
    
    /**
     * Sets the method used to authenticate the user.
     *
     * @param authnMethod The method used to authenticate the user.
     */
    public void setAuthenticationMethod(String authnMethod) {
	this.authnMethod = authnMethod;
    }
    
    
    /**
     * Gets the {@link Session} ID
     *
     * @return the Session id.
     */
    public String getSessionID() {
	return this.sessionID;
    }
    
    
    /**
     * Sets the {@link Session} ID
     *
     * @param sessionID the Session ID
     */
    public void setSessionID(String sessionID) {
	this.sessionID = sessionID;
    }
}
