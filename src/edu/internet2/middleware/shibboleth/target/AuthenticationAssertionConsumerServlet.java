/*
 * AuthenticatonAssertionConsumerServlet
 * 
 * The Shibboleth function previous known as the SHIRE.
 * 
 * Authentication Assertion Consumer is the SAML 2.0 term for what the
 * SHIRE does. A SAML Assertion containing an Authentication statement
 * with the "principal" identifier value equal to the handle vended by
 * the Handle Server is received from the Browser. The Handle Server
 * generated a form, prefilled it with a Bin64 encoding of the SAML
 * statement, and included Javascript to automatically submit the form
 * to this URL.
 * 
 * All HTTP, HTML, and servlet logic is localized to this layer of
 * modules. Any information must be extracted from the Servlet API
 * to be passed directly to Shibboleth.
 * 
 * The work is done by a ShibPOSTProfile object. It takes the Bin64
 * encoded string, converts it to a SAMLObject, verifies structure,
 * and validates signatures.
 * 
 * The resulting Authentication Assertion SAML statement is passed
 * to Session Manager to create a new session. This process feeds
 * back a session identifier that becomes the value of a Cookie sent
 * back to the Browser to track the session.
 * 
 * If the decision is made to fetch attributes immediately, the 
 * Session object can be passed to the static AttributeRequestor
 * service. It generates a ShibBinding, sends a request to the AA,
 * validates the response, applies AAP, and stores the resulting 
 * SAML Attribute Assertion in the Session object.
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
package edu.internet2.middleware.shibboleth.target;

import java.io.IOException;
import java.util.Collections;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAuthenticationStatement;
import org.opensaml.SAMLException;
import org.opensaml.SAMLPOSTProfile;
import org.opensaml.SAMLResponse;
import org.w3c.dom.Element;
import org.apache.log4j.FileAppender;
import org.apache.log4j.Layout;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.apache.xml.security.Init;

import x0.maceShibbolethTargetConfig1.SessionsDocument.Sessions;

import edu.internet2.middleware.commons.log4j.ThreadLocalAppender;
import edu.internet2.middleware.shibboleth.common.Credentials;
import edu.internet2.middleware.shibboleth.metadata.MetadataException;
import edu.internet2.middleware.shibboleth.resource.AuthenticationFilter;
import edu.internet2.middleware.shibboleth.target.ServiceProviderConfig.ApplicationInfo;

/**
 * AuthenticatonAssertionConsumerServlet
 * 
 * @author Howard Gilbert
 */
public class AuthenticationAssertionConsumerServlet extends HttpServlet {

	private static Logger log = null;
	
	private static ServiceProviderContext context = ServiceProviderContext.getInstance();
	
	private Element			configuration;
	private Credentials				credentials;
	
	public static final String SESSIONPARM =
	    "ShibbolethSessionId";
	
	
	public void init() throws ServletException {
		super.init();
		ServletContext servletContext = this.getServletContext();
		
		Init.init();

		// Initialize logging specially
		Logger targetLogger = Logger.getLogger("edu.internet2.middleware");
		String logname = servletContext.getRealPath("/diagnose/initialize.log");
		Layout initLayout = new PatternLayout("%d{HH:mm} %-5p %m%n");
		
		try {
            FileAppender initLogAppender = new FileAppender(initLayout,logname);
            ThreadLocalAppender threadAppender = new ThreadLocalAppender();
            threadAppender.setLayout(initLayout);
            targetLogger.setAdditivity(false);
            targetLogger.addAppender(initLogAppender);
            targetLogger.addAppender(threadAppender);
            targetLogger.setLevel(Level.DEBUG);
        } catch (IOException e) {
            e.printStackTrace();
        }
		
/*		ConsoleAppender rootAppender = new ConsoleAppender();
		rootAppender.setWriter(new PrintWriter(System.out));
		rootAppender.setName("stdout");
		targetLogger.addAppender(rootAppender);

		// rootAppender.setLayout(new PatternLayout("%-5p %-41X{serviceId} %d{ISO8601} (%c:%L) - %m%n"));
		// Logger.getRootLogger().setLevel((Level) Level.DEBUG);
		Logger.getRootLogger().setLevel((Level) Level.INFO);
		rootAppender.setLayout(new PatternLayout("%d{ISO8601} %-5p %-41X{serviceId} - %m%n"));
*/
		log = Logger.getLogger(AuthenticationAssertionConsumerServlet.class.getName());
		
		ServletContextInitializer.initServiceProvider(servletContext);
		AuthenticationFilter.setFilterSupport(new FilterSupportImpl());
		
	}



	/**
	 * Accept the SAML Assertion post from the HS.
	 * 
	 * @param request the request send by the client to the server
	 * @param response the response send by the server to the client
	 * @throws ServletException if an error occurred
	 * @throws IOException if an error occurred
	 */
	public void doPost(
		HttpServletRequest request,
		HttpServletResponse response)
		// throws ServletException, IOException 
		{
	    ServletContextInitializer.beginService(request,response);
		try {
            ServiceProviderConfig config = context.getServiceProviderConfig();
            
            String ipaddr = request.getRemoteAddr();
            
            // URL of Resource that triggered authorization
            String target = request.getParameter("TARGET");
            
            // Bin64 encoded SAML Authentication Assertion from HS
            String assertparm = request.getParameter("SAMLResponse");
            byte [] bin64Assertion = assertparm.getBytes();
            
            // Map the Resource URL into an <Application>
            String applicationId = config.mapRequest(target);
            ApplicationInfo appinfo = config.getApplication(applicationId);
            Sessions appSessionValues = appinfo.getApplicationConfig().getSessions();
            
            // Sanity check:
            // I am the SHIRE. So the SHIRE URL should be the one in the 
            // HttpRequest. However, it might have been stepped on by a filter
            // or frontend. This is the configured cannonical URL that was 
            // passed to the filter, sent to the HS, and used by the browser
            // in the redirect. If I need (for whatever reason) to pass a 
            // Shire URL to the POST processing, lets use the configured one
            String shireURL = appSessionValues.getShireURL();
            
            // Provider ID of me, the Service Provider, for this application
            String providerId = appinfo.getApplicationConfig().getProviderId();
            String[] audiences = new String[1];
            audiences[0]=providerId;
            
            if (appSessionValues.getShireSSL()&& // Requires SSL
            		!request.isSecure()) {       // isn't SSL
            	log.error("Authentication Assersion not posted over SSL.");
            	response.sendRedirect("/shireError.html");
            }
            
            log.debug("Authentication received from "+ipaddr+" for "+target+
                        "(application:"+applicationId+") (Provider:"+providerId+")");
            
            // Unfortunately, the previous mix of Java and C had about 100 things
            // called "providers". In this particular case, we are passing to 
            // the POST processing layer an empty StringBuffer into which will be
            // placed a second return value (tricky!). This will be the ID of the
            // Origin. 
            StringBuffer pproviderId = new StringBuffer();
            
            SAMLResponse samldata = null;	
            SAMLAssertion assertion = null;
            SAMLAuthenticationStatement authstmt = null;
            try { 
            	ShibPOSTProfile profile = new ShibPOSTProfile(applicationId);
            	samldata = profile.accept(
            	        bin64Assertion, // Assertion from POST of Form field
            	        shireURL,   // My URL (Why??)
            	        60, 
            	        audiences,  // My "Provider" (Entity) ID
            	        pproviderId // HS "Provider" (Entity) ID returned
            	        );
            	
                assertion = SAMLPOSTProfile.getSSOAssertion(samldata,
                        Collections.singleton(providerId));
                authstmt = SAMLPOSTProfile.getSSOStatement(assertion);
            	
            } catch (SAMLException e) {
            	log.error("Authentication Assertion had invalid format.");
            	response.sendRedirect("/shireError.html");
            	return;
            }
            catch (MetadataException e) {
            	log.error("Authentication Assertion source not found in Metadata.");
            	response.sendRedirect("/shireError.html");
            	return;
            }

            
            // The Authentication Assertion gets placed in a newly created
            // Session object. Later, someone will get an Attribute Assertion
            // and add it to the Session. The SessionID key is returned to
            // the Browser as a Cookie.
            SessionManager sessionManager = context.getSessionManager();
            String sessionid = sessionManager.newSession(
                    applicationId, ipaddr, pproviderId.toString(), assertion, authstmt);
            Cookie cookie = new Cookie("ShibbolethSPSession",sessionid);
            response.addCookie(cookie);
            
            // Very agressive attribute fetch rule 
            // Get the Attributes immediately! [good for debugging]
            Session session = sessionManager.findSession(sessionid, applicationId);
            boolean gotattributes = AttributeRequestor.fetchAttributes(session);
            if (!gotattributes)
            	response.sendRedirect("/shireError.html");
            
            log.debug(SessionManager.dumpAttributes(session));
            
            response.sendRedirect(target+"?"+SESSIONPARM+"="+sessionid);
        } catch (IOException e) {
            // A sendRedirect() failed. 
            // This can only happen if the user closed the Browser.
            // Nothing to do
        } finally {
            ServletContextInitializer.finishService(request,response);
        }

	}
	
    protected void doGet(HttpServletRequest arg0, HttpServletResponse arg1)
    	throws ServletException, IOException {
        // TODO Auto-generated method stub
        super.doGet(arg0, arg1);
    }
	

}
