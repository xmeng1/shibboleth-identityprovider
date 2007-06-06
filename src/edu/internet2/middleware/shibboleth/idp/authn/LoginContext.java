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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.joda.time.DateTime;

/**
 * Login context created by a profile handler and interpreted by the authentication package.
 * 
 * Two properties are tracked by default:
 * 
 * <code>forceAuth</code> - Should user authentiation be forced. <code>passiveAuth</code> - Should user
 * authentication not control the UI.
 * 
 * A Map&lt;String, Object&gt; is provided to store other properties. Alternatively, a profile handler may create a
 * subclass of LoginContext with extra fields.
 * 
 * LoginContexts should be created by a profile handler when authentication is needed. Once control has returned to the
 * profile handler, it should remove the LoginContext from the HttpSession.
 * 
 * The {@link AuthenticationManager} or an {@link AuthenticationHandler} should set the
 * {@link LoginContext#setAuthenticationAttempted()}, {@link LoginContext#setAuthnOK(boolean)},
 * {@link LoginContext#setAuthnFailure(String)}, {@link LoginContext#{setAuthenticationDuration(long)}
 * {@link LoginContext#setAuthenticationInstant(DateTime)} appropriately.
 * 
 */
public class LoginContext implements Serializable {

    /** the key in a HttpSession where login contexts are stored. */
    public static final String LOGIN_CONTEXT_KEY = "shib2.logincontext";
    
    /** Serial version UID. */
    private static final long serialVersionUID = 4268661186941572372L;

    /** Entity ID of the relying party. */
    private String relyingPartyId;

    /** Should user authentication be forced. */
    private boolean forceAuth;

    /** Must authentication not interact with the UI. */
    private boolean passiveAuth;

    /** a catch-all map for other properties. */
    private Map<String, Serializable> propsMap = new ConcurrentHashMap<String, Serializable>();

    /** The ProfileHandler URL. */
    private String profileHandlerURL;

    /** The AuthenticationManager's URL. */
    private String authnManagerURL;

    /** has authentication been attempted yet. */
    private boolean authnAttempted;

    /** The id of the authenticated user. */
    private String userID;

    /** Did authentication succceed? */
    private boolean authenticationOK;

    /** Optional failure message. */
    private String authnFailureMessage;

    /** The instant of authentication. */
    private DateTime authnInstant;

    /** The duration of authentication. */
    private long authnDuration;

    /** The method used to authenticate the user. */
    private String authnMethod;

    /** The session id. */
    private String sessionID;

    /** Creates a new instance of LoginContext. */
    public LoginContext() {
    }

    /**
     * Creates a new instance of LoginContext.
     * 
     * @param force if the authentication manager must reauth the user.
     * @param passive if the authentication manager must not interact with the users UI.
     */
    public LoginContext(boolean force, boolean passive) {

        forceAuth = force;
        passiveAuth = passive;
    }

    /**
     * Gets the entity ID of the relying party.
     * 
     * @return entity ID of the relying party
     */
    public String getRelyingPartyId() {
        return relyingPartyId;
    }

    /**
     * Gets the entity ID of the relying party.
     * 
     * @param id entity ID of the relying party
     */
    public void setRelyingParty(String id) {
        relyingPartyId = id;
    }

    /**
     * Returns if authentication must be forced.
     * 
     * @return <code>true</code> if the authentication manager must reauth the user.
     */
    public boolean getForceAuth() {
        return forceAuth;
    }

    /**
     * Returns if authentication must be passive.
     * 
     * @return <code>true</code> if the authentication manager must not interact with the users UI.
     */
    public boolean getPassiveAuth() {
        return passiveAuth;
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
        return propsMap.get(key);
    }

    /**
     * Sets an optional property object.
     * 
     * If an object is already associated with key, it will be overwritten.
     * 
     * @param key The key to set.
     * @param obj The object to associate with key.
     */
    public void setProperty(String key, final Serializable obj) {
        propsMap.put(key, obj);
    }

    /**
     * Sets if authentication succeeded.
     * 
     * @param authnOK if authentication succeeded;
     */
    public void setAuthenticationOK(boolean authnOK) {
        this.authenticationOK = authnOK;
    }

    /**
     * Returns if authentication succeeded.
     * 
     * @return <code>true</code> is the user was successfully authenticated.
     */
    public boolean getAuthenticationOK() {
        return authenticationOK;
    }

    /**
     * Sets the optional authentication failure message.
     * 
     * @param failureMessage A description of why authN failed.
     */
    public void setAuthenticationFailureMessage(String failureMessage) {
        authnFailureMessage = failureMessage;
    }

    /**
     * Returns the optional authentication failure message.
     * 
     * @return The failure message, or <code>null</code> is none was set.
     */
    public String getAuthenticationFailureMessage() {
        return authnFailureMessage;
    }

    /**
     * Set if authentication has been attempted.
     * 
     * This method should be called by an {@link AuthenticationHandler} while processing a request.
     */
    public void setAuthenticationAttempted() {
        authnAttempted = true;
    }

    /**
     * Returns if authentication has been attempted for this user.
     * 
     * @return if authentication has been attempted for this user
     */
    public boolean getAuthenticationAttempted() {
        return authnAttempted;
    }

    /**
     * Sets the ID of the authenticated user.
     * 
     * @param id The userid.
     */
    public void setUserID(String id) {
        userID = id;
    }

    /**
     * Returns the ID of the authenticated user.
     * 
     * @return the ID of the user, or <code>null</code> if authentication failed.
     */
    public String getUserID() {
        return userID;
    }

    /**
     * Gets the ProfileHandler URL.
     * 
     * @return the URL of the profile handler that is invoking the Authentication Manager.
     */
    public String getProfileHandlerURL() {
        return profileHandlerURL;
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
    public String getAuthenticationManagerURL() {
        return authnManagerURL;
    }

    /**
     * Sets the AuthenticationManager's URL.
     * 
     * @param authnManagerURL the URL of the AuthenticationManager.
     */
    public void setAuthenticationManagerURL(String authnManagerURL) {
        this.authnManagerURL = authnManagerURL;
    }

    /**
     * Gets the authentication instant.
     * 
     * @return The instant of authentication, or <code>null</code> if none was set.
     */
    public DateTime getAuthenticationInstant() {
        return authnInstant;
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
        return authnDuration;
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
        return authnMethod;
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
        return sessionID;
    }

    /**
     * Sets the {@link Session} ID
     * 
     * @param sessionID the Session ID
     */
    public void setSessionID(String sessionID) {
        this.sessionID = sessionID;
    }

    /**
     * Return the acceptable authentication handler URIs for authenticating this user. If no authentication methods are
     * preferred the resultant list will be empty.
     * 
     * @return an array of URIs
     */
    public List<String> getRequestedAuthenticationMethods() {
        return new ArrayList<String>();
    }
}
