/*
 * SessionManager creates, maintains, and caches Session objects.
 * 
 * The SessionManager is a singleton object.
 * A reference to the unique SessionManger object can always be obtained
 * from the ServiceProviderContext.getSessionManager() method.
 * 
 * Sessions should only be created, modified, and deleted through methods
 * of this class so that the in-memory collection and any disk Cache can
 * also be changed. Disk cache implementations are referenced through the
 * SessionCache interface. 
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

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

import org.apache.log4j.Logger;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAttribute;
import org.opensaml.SAMLAttributeStatement;
import org.opensaml.SAMLAuthenticationStatement;
import org.opensaml.SAMLResponse;
import org.opensaml.SAMLStatement;

import x0.maceShibbolethTargetConfig1.SessionsDocument.Sessions;

import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderConfig.ApplicationInfo;

/**
 * <p>SessionManager manages the memory and disk Cache of Session objects.</p>
 * 
 * <p>setSessionCache(SessionCache s) is an "IOC" wiring point. Pass it
 * an implementation of the SessionCache interface.</p> 
 * 
 * @author Howard Gilbert
 */
public class SessionManager {
	
	/*
	 * Sessions can be saved using any Persistance Framework. If a Cache
	 * is created, the following pointer is filled in and we start to 
	 * use it.
	 */
	private static Logger log = Logger.getLogger(SessionManager.class.getName());
	
	private SessionCache cache = null; // By default, use memory cache only
	
	private TreeMap sessions = new TreeMap(); // The memory cache of Sessions
	
	private static ServiceProviderContext context = ServiceProviderContext.getInstance();

	private static SecureRandom rand = new SecureRandom();
	private static final String table = "0123456789" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"+
		"abcdefgjikjlmnopqrstuvwxyz"+
		"$@";
	public String generateKey() {
	    byte[] trash = new byte[16];
	    char[] ctrash = new char[16];
	    do {
	        rand.nextBytes(trash);
	        for (int i=0;i<16;i++) {
	            trash[i]|=0x3f;
	            ctrash[i]=(char)table.charAt(trash[i]);
	        }
	    } while (null!=sessions.get(ctrash));
	    return new String(ctrash);
	}
	
	
	
	public synchronized Session findSession(String sessionId, String applicationId ) {
		Session s = (Session) sessions.get(sessionId);
		if (s==null)
			return null;
		if (null==s.getAuthenticationAssertion())
		    return null;
		if (!applicationId.equals(s.getApplicationId()))
			return null;
		return s;
	}

	private synchronized Session findEmptySession(String sessionId) {
		Session s = (Session) sessions.get(sessionId);
		if (s==null)
			return null;
		if (null!=s.getAuthenticationAssertion())
		    return null;
		return s;
	}
	
	
	protected synchronized void add(Session s) {
		sessions.put(s.getKey(), s);
		if (cache!=null)
			cache.add(s);
	}
	
	protected synchronized void update(Session s) {
		sessions.put(s.getKey(), s);
		if (cache!=null)
			cache.update(s);
	}
	
	protected synchronized void remove(Session s) {
		sessions.remove(s.getKey());
		if (cache!=null)
			cache.remove(s);
	}
	

	/**
	 * Test for valid Session
	 * 
	 * @param sessionId      typically, the cookie value from client browser
	 * @param applicationId  id of target application asking about session
	 * @param ipaddr         null, or IP address of client
	 * @return
	 */
	public 
			boolean 
	isValid(
			String sessionId,   
			String applicationId, 
			String ipaddr         
			){
		Session session = findSession(sessionId,applicationId);
		ServiceProviderConfig.ApplicationInfo application = context.getServiceProviderConfig().getApplication(applicationId);
		if (session==null)
			return false; // Cookie value did not match cached session
		if (application == null)
			return false; // ApplicationConfig ID invalid
		if (ipaddr!=null && !ipaddr.equals(session.getIpaddr()))
			return false; // Client coming from a different machine
		// check for timeout
		// Note: RPC prefetches attributes here
		return true;
	}

	
	/**
	 * Store Principal information identified by generated UUID.<br>
	 * Called from Authentication Assertion Consumer [SHIRE]
	 * 
	 * @param applicationId The application for this session
	 * @param ipaddr The client's remote IP address from HTTP
	 * @param entityId The Entity of the AA issuing the authentication
	 * @param assertion Assertion in case one needs more data
	 * @param authentication subset of assertion with handle
	 * @return String (UUID) to go in the browser cookie
	 */
	public 
			String 
	newSession(
			String applicationId, 
			String ipaddr,
			String entityId,
			SAMLAssertion assertion,
			SAMLAuthenticationStatement authenticationStatement,
			String emptySessionId // may be null
			){
		
		ServiceProviderConfig config = context.getServiceProviderConfig();
		ApplicationInfo appinfo = config.getApplication(applicationId);
		Sessions appSessionValues = appinfo.getApplicationConfig().getSessions();
		
		String sessionId = null;
		
		Session session;
		if (emptySessionId==null) {
		    session = new Session(generateKey());
		} else {
		    session = findEmptySession(emptySessionId);
		    if (session==null) {
			    session = new Session(generateKey());
		    }
		}
		session.setApplicationId(applicationId);
		session.setIpaddr(ipaddr);
		session.setEntityId(entityId);
		
		session.setAuthenticationAssertion(assertion);
		session.setAuthenticationStatement(authenticationStatement);
		
		session.setLifetime(appSessionValues.getLifetime());
		session.setTimeout(appSessionValues.getTimeout());
		
		sessionId = session.getKey();

		// This static method finds its unique instance variable
		add(session);
	    log.debug("New Session created "+sessionId);

		return sessionId;
	}
	/**
	 * <p>IOC wiring point to plug in an external SessionCache implementation.
	 * </p>
	 * 
	 * @param cache Plugin object implementing the SessionCache interface
	 */
	public synchronized void 
	setCache(
			SessionCache cache) {
		
	    log.info("Enabling Session Cache");
		/*
		 * The following code supports dynamic switching from
		 * one cache to another if, for example, you decide
		 * to change databases without restarting Shibboleth.
		 * Whether this is useful or not is a matter of dispute.
		 */
		if (this.cache!=null) { // replacing an old cache
			this.cache.close(); // close it and leave it for GC
			return;
		}
		
		this.cache = cache; 
		
		/*
		 * Make sure the Cache knows about in memory sessions
		 * 
		 * Note: The cache should probably be wired prior to letting
		 * the Web server process requests, so in almost all cases this
		 * block will not be neeed. However, we may allow the configuration
		 * to change dynamically from uncached to cached in the middle
		 * of a Shibboleth run, and this allows for that possiblity.
		 */
		if (sessions.size()!=0) {
			for (Iterator i=sessions.values().iterator();i.hasNext();) {
				Session s = (Session) i.next();
				cache.add(s);
			}
		}
		
		/*
		 * Now load any Sessions in the cache that are not in memory
		 * (typically after a reboot).
		 */
		cache.reload(sessions);
	}
	
	public static StringBuffer dumpAttributes(Session session) {
	    StringBuffer sb = new StringBuffer();
        SAMLResponse attributeResponse = session.getAttributeResponse();
        Iterator assertions = attributeResponse.getAssertions();
        while (assertions.hasNext()) {
            SAMLAssertion assertion = (SAMLAssertion) assertions.next();
            Iterator statements = assertion.getStatements();
            while (statements.hasNext()) {
                SAMLStatement statement = (SAMLStatement) statements.next();
                if (statement instanceof SAMLAttributeStatement) {
                    SAMLAttributeStatement attributeStatement = 
                        (SAMLAttributeStatement) statement;
                    
                    // Foreach Attribute in the AttributeStatement
                    Iterator attributes = attributeStatement.getAttributes();
                    while (attributes.hasNext()) {
                        SAMLAttribute attribute = 
                            (SAMLAttribute) attributes.next();
                        String name = attribute.getName();
                        String namespace = attribute.getNamespace();
                        Iterator values = attribute.getValues();
                        while (values.hasNext()){
                            String val = (String) values.next();
                            sb.append(name+" "+namespace+" "+val);
                        }
                    }
                }
            }
        }
	    
	    return sb;
	}

	public static Map /*<String,String>*/
	mapAttributes(Session session) {
	    Map /*<String,String>*/attributeMap = new HashMap/*<String,String>*/();
	    StringBuffer sb = new StringBuffer();
        SAMLResponse attributeResponse = session.getAttributeResponse();
        Iterator assertions = attributeResponse.getAssertions();
        while (assertions.hasNext()) {
            SAMLAssertion assertion = (SAMLAssertion) assertions.next();
            Iterator statements = assertion.getStatements();
            while (statements.hasNext()) {
                SAMLStatement statement = (SAMLStatement) statements.next();
                if (statement instanceof SAMLAttributeStatement) {
                    SAMLAttributeStatement attributeStatement = 
                        (SAMLAttributeStatement) statement;
                    
                    // Foreach Attribute in the AttributeStatement
                    Iterator attributes = attributeStatement.getAttributes();
                    while (attributes.hasNext()) {
                        SAMLAttribute attribute = 
                            (SAMLAttribute) attributes.next();
                        String name = attribute.getName();
                        String namespace = attribute.getNamespace();
                        ArrayList list = new ArrayList();
                        Iterator values = attribute.getValues();
                        String val="";
                        while (values.hasNext()){
                            val = (String) values.next();
                            list.add(val);
                        }
                        if (list.size()==1)
                            attributeMap.put(name,val);
                        else
                            attributeMap.put(name,list);
                    }
                }
            }
        }
	    
	    return attributeMap;
	}
	
	
}
