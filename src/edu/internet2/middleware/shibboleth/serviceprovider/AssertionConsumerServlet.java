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
 */
package edu.internet2.middleware.shibboleth.serviceprovider;

import java.io.File;
import java.io.IOException;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.SAMLException;
import org.opensaml.SAMLBrowserProfile;
import org.opensaml.SAMLResponse;
import org.opensaml.SAMLBrowserProfile.BrowserProfileResponse;
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
import edu.internet2.middleware.shibboleth.common.ShibBrowserProfile;
import edu.internet2.middleware.shibboleth.metadata.MetadataException;
import edu.internet2.middleware.shibboleth.resource.AuthenticationFilter;
import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderConfig.ApplicationInfo;

/**
 * AuthenticatonAssertionConsumerServlet
 * 
 * @author Howard Gilbert
 */
public class AssertionConsumerServlet extends HttpServlet {

	private static Logger log = null;
	
	private static ServiceProviderContext context = ServiceProviderContext.getInstance();
	
	private Element			configuration = null;
	private Credentials		credentials = null;
	
	public static final String SESSIONPARM =
	    "ShibbolethSessionId";
	
	
	public void init() throws ServletException {
		super.init();
		ServletContext servletContext = this.getServletContext();
		
		Init.init();

		// Initialize logging specially
		Logger targetLogger = Logger.getLogger("edu.internet2.middleware");
		Logger samlLogger = Logger.getLogger("org.opensaml");
		File diagdir = new File(servletContext.getRealPath("/diagnose"));
		diagdir.mkdirs();
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
            samlLogger.addAppender(threadAppender);
            samlLogger.setLevel(Level.DEBUG);
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
		log = Logger.getLogger(AssertionConsumerServlet.class.getName());
		
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
            // XXX: I added support to the profile for extracting TARGET, but
            // it's not too critical in Java since you can grab it easily anyway.
            // Might be better in the 2.0 future though, since the bindings get trickier.
            String target = request.getParameter("TARGET");
            
            // Map the Resource URL into an <Application>
            String applicationId = config.mapRequest(target);
            ApplicationInfo appinfo = config.getApplication(applicationId);
            Sessions appSessionValues = appinfo.getApplicationConfig().getSessions();
            String shireURL = request.getRequestURL().toString();
            String providerId = appinfo.getApplicationConfig().getProviderId();
            
           
            if (appSessionValues.getShireSSL()&& // Requires SSL
            		!request.isSecure()) {       // isn't SSL
            	log.error("Authentication Assersion not posted over SSL.");
            	try {
                    response.sendRedirect("/shibboleth/shireError.html");
                } catch (IOException e1) {
                }
            	return;
            }
            
            log.debug("Authentication received from "+ipaddr+" for "+target+
                        "(application:"+applicationId+") (Provider:"+providerId+")");

            String sessionId = createSessionFromPost(ipaddr, request, applicationId, shireURL, providerId, null);
            
            Cookie cookie = new Cookie("ShibbolethSPSession",sessionId);
            response.addCookie(cookie);
            
            try {
				if (target.equals("SendAttributesBackToMe")) {
					ServletOutputStream outputStream = response.getOutputStream();
					response.setContentType("text/xml");
					Session session = context.getSessionManager().findSession(sessionId,applicationId);
					SAMLResponse attributeResponse = session.getAttributeResponse();
					outputStream.print(attributeResponse.toString());
				} else {
					response.sendRedirect(target+"?"+SESSIONPARM+"="+sessionId);
				}
            }
            catch (IOException e) {
            }
        }
        catch (MetadataException e) {
            log.error("Authentication Assertion source not found in Metadata.");
            try {
                response.sendRedirect("/shibboleth/shireError.html");
            }
            catch (IOException e1) {
            }
        }
        catch (SAMLException e) {
            log.error("Authentication Assertion had invalid format.");
            try {
                response.sendRedirect("/shibboleth/shireError.html");
            }
            catch (IOException e1) {
            }
        }
        finally {
            ServletContextInitializer.finishService(request,response);
        }
	}
	
    /**
     * Create a Session object from SHIRE POST data
     * 
     * @param ipaddr IP Address of Browser
     * @param bin64Assertion Authentication assertion from POST
     * @param applicationId from RequestMap
     * @param shireURL 
     * @param providerId Our Entity name
     * @return random key of Session
     * @throws SAMLException
     */
    public static 
    String createSessionFromPost(
            String ipaddr, 
            HttpServletRequest req, 
            String applicationId, 
            String shireURL, 
            String providerId,
            String emptySessionId
            ) 
    throws SAMLException {
        String sessionid=null;
        StringBuffer pproviderId = // Get back IdP Entity name from SAML
            new StringBuffer();
        String[] audiences = new String[1];
        audiences[0]=providerId;
        
        ShibBrowserProfile profile = new ShibBrowserProfile(applicationId);
        BrowserProfileResponse samldata = profile.receive(
                pproviderId,
                req,
                shireURL,   // My URL (Why??) To prevent attackers from redirecting messages. 
                SAMLBrowserProfile.PROFILE_POST,    // TODO: support both profiles 
                context.getReplayCache(),
                null,
                1
        );
        
        // TODO: Audience/condition checking is now the profile caller's job.
        
        // The Authentication Assertion gets placed in a newly created
        // Session object. Later, someone will get an Attribute Assertion
        // and add it to the Session. The SessionID key is returned to
        // the Browser as a Cookie.
        SessionManager sessionManager = context.getSessionManager();
        sessionid = sessionManager.newSession(
                applicationId, 
                ipaddr, 
                pproviderId.toString(), 
                samldata.assertion, 
                samldata.authnStatement,
                emptySessionId);
        
        // Very agressive attribute fetch rule 
        // Get the Attributes immediately! [good for debugging]
        Session session = sessionManager.findSession(sessionid, applicationId);
        AttributeRequestor.fetchAttributes(session);

        return sessionid;
    }



    protected void doGet(HttpServletRequest arg0, HttpServletResponse arg1)
    	throws ServletException, IOException {
        // TODO Auto-generated method stub
        super.doGet(arg0, arg1);
    }
	

}