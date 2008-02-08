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
 * <code>forceAuth</code> - Should user authentication be forced. <code>passiveAuth</code> - Should user
 * authentication not control the UI.
 * 
 * A Map&lt;String, Object&gt; is provided to store other properties. Alternatively, a profile handler may create a
 * subclass of LoginContext with extra fields.
 * 
 * LoginContexts should be created by a profile handler when authentication is needed. Once control has returned to the
 * profile handler, it should remove the LoginContext from the HttpSession.
 * 
 * The {@link AuthenticationEngine} or an {@link LoginHandler} should set the
 * {@link LoginContext#setAuthenticationAttempted()}, {@link LoginContext#setPrincipalAuthenticated(boolean)},
 * {@link LoginContext#setAuthenticationFailure(AuthenticationException)},
 * {@link LoginContext#{setAuthenticationDuration(long)} {@link LoginContext#setAuthenticationInstant(DateTime)}
 * appropriately.
 */
public class LoginContext implements Serializable {

    /** the key in a HttpSession where login contexts are stored. */
    public static final String LOGIN_CONTEXT_KEY = "shib2.logincontext";

    /** Serial version UID. */
    private static final long serialVersionUID = -8764003758734956911L;

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

    /** The authentication engine's URL. */
    private String authnEngineURL;

    /** has authentication been attempted yet. */
    private boolean authnAttempted;

    /** The id of the authenticated user. */
    private String principalName;

    /** Did authentication succeed? */
    private boolean principalAuthenticated;

    /** Exception that occured during authentication. */
    private AuthenticationException authnException;

    /** The instant of authentication. */
    private DateTime authnInstant;

    /** The duration of authentication. */
    private long authnDuration;

    /** The method used to authenticate the user. */
    private String authnMethod;

    /** The session id. */
    private String sessionID;

    /** List of request authentication methods. */
    private ArrayList<String> requestAuthenticationMethods;

    /** Creates a new instance of LoginContext. */
    public LoginContext() {
        requestAuthenticationMethods = new ArrayList<String>();
    }

    /**
     * Creates a new instance of LoginContext.
     * 
     * @param force if the authentication manager must re-authenticate the user.
     * @param passive if the authentication manager must not interact with the users UI.
     */
    public LoginContext(boolean force, boolean passive) {
        forceAuth = force;
        passiveAuth = passive;
        requestAuthenticationMethods = new ArrayList<String>();
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
     * @return <code>true</code> if the authentication manager must re-authenticate the user.
     */
    public boolean isForceAuthRequired() {
        return forceAuth;
    }

    /**
     * Returns if authentication must be passive.
     * 
     * @return <code>true</code> if the authentication manager must not interact with the users UI.
     */
    public boolean isPassiveAuthRequired() {
        return passiveAuth;
    }

    /**
     * Sets if authentication must be forced.
     * 
     * @param force if the authentication manager must re-authenticate the user.
     */
    public void setForceAuthRequired(boolean force) {
        forceAuth = force;
    }

    /**
     * Sets if authentication must be passive.
     * 
     * @param passive if the authentication manager must not interact with the users UI.
     */
    public void setPassiveAuthRequired(boolean passive) {
        passiveAuth = passive;
    }

    /**
     * Get an optional property object.
     * 
     * @param key The key in the properties Map.
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
    public void setPrincipalAuthenticated(boolean authnOK) {
        this.principalAuthenticated = authnOK;
    }

    /**
     * Returns if authentication succeeded.
     * 
     * @return <code>true</code> is the user was successfully authenticated.
     */
    public boolean isPrincipalAuthenticated() {
        return principalAuthenticated;
    }

    /**
     * Sets the error that occurred during authentication.
     * 
     * @param error error that occurred during authentication
     */
    public void setAuthenticationFailure(AuthenticationException error) {
        authnException = error;
    }

    /**
     * Gets the error that occurred during authentication.
     * 
     * @return error that occurred during authentication
     */
    public AuthenticationException getAuthenticationFailure() {
        return authnException;
    }

    /**
     * Set if authentication has been attempted.
     * 
     * This method should be called by an {@link LoginHandler} while processing a request.
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
    public void setPrincipalName(String id) {
        principalName = id;
    }

    /**
     * Returns the ID of the authenticated user.
     * 
     * @return the ID of the user, or <code>null</code> if authentication failed.
     */
    public String getPrincipalName() {
        return principalName;
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
     * @param url The URL of the profile handler that invoked the AuthenticationManager/
     */
    public void setProfileHandlerURL(String url) {
        profileHandlerURL = url;
    }

    /**
     * Gets the authentication engine's URL.
     * 
     * @return the URL of the authentication engine
     */
    public String getAuthenticationEngineURL() {
        return authnEngineURL;
    }

    /**
     * Sets the authentication engine's URL.
     * 
     * @param url the URL of the authentication engine
     */
    public void setAuthenticationEngineURL(String url) {
        authnEngineURL = url;
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
     * @param instant The instant of authentication.
     */
    public void setAuthenticationInstant(final DateTime instant) {
        authnInstant = instant;
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
     * @param duration The duration of authentication.
     */
    public void setAuthenticationDuration(long duration) {
        authnDuration = duration;
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
     * @param method The method used to authenticate the user.
     */
    public void setAuthenticationMethod(String method) {
        authnMethod = method;
    }

    /**
     * Gets the {@link edu.internet2.middleware.shibboleth.idp.session.Session} ID.
     * 
     * @return the Session id
     */
    public String getSessionID() {
        return sessionID;
    }

    /**
     * Sets the {@link edu.internet2.middleware.shibboleth.idp.session.Session} ID.
     * 
     * @param id the Session ID
     */
    public void setSessionID(String id) {
        sessionID = id;
    }

    /**
     * Return the acceptable authentication handler URIs, in preference order, for authenticating this user. If no
     * authentication methods are preferred the resultant list will be empty.
     * 
     * @return an list of authentication method identifiers
     */
    public List<String> getRequestedAuthenticationMethods() {
        return requestAuthenticationMethods;
    }
}