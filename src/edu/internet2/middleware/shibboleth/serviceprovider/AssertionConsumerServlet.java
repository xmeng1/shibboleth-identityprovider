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

import java.io.IOException;
import java.util.Iterator;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAttributeStatement;
import org.opensaml.SAMLAudienceRestrictionCondition;
import org.opensaml.SAMLCondition;
import org.opensaml.SAMLException;
import org.opensaml.SAMLResponse;
import org.opensaml.SAMLStatement;
import org.opensaml.SAMLBrowserProfile.BrowserProfileRequest;
import org.opensaml.SAMLBrowserProfile.BrowserProfileResponse;

import edu.internet2.middleware.shibboleth.common.ShibBrowserProfile;
import edu.internet2.middleware.shibboleth.metadata.MetadataException;
import edu.internet2.middleware.shibboleth.resource.AuthenticationFilter;
import edu.internet2.middleware.shibboleth.resource.FilterUtil;
import edu.internet2.middleware.shibboleth.resource.FilterSupport.NewSessionData;
import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderConfig.ApplicationInfo;

/**
 * Process the Authentication Assertion POST data to create a Session.
 * 
 * @author Howard Gilbert
 */
public class AssertionConsumerServlet extends HttpServlet {

    // There is currently no reason for a Cookie from the SP
	// private static final String COOKIEPREFIX = "edu.internet2.middleware.shibboleth.session.";

	private static Logger log = Logger.getLogger(AssertionConsumerServlet.class.getName());
	
	private static ServiceProviderContext context = ServiceProviderContext.getInstance();
	
    // The query string parameter appended when Redirecting to the RM
	public static final String SESSIONPARM =
	    "ShibbolethSessionId";
	
	
	public void init() throws ServletException {
		super.init();
		ServletContext servletContext = this.getServletContext();
		
		// Note: the ServletContext should have been initialized by the Listener
		ServletContextInitializer.initServiceProvider(servletContext);
		
		// Establish linkage between the SP context and the RM Filter class
		AuthenticationFilter.setFilterSupport(new FilterSupportImpl());
	}



	/**
	 * Process the POST (or Artifact GET) from the Browser after SSO
	 */
	public void doPost(
		HttpServletRequest request,
		HttpServletResponse response)
		{
        
        // Initialize Request level (ThreadLocal) tracking
	    ServletContextInitializer.beginService(request,response);
        
        String contextPath = request.getContextPath();
        ServiceProviderConfig config = context.getServiceProviderConfig();
        
        String ipaddr = request.getRemoteAddr();
        String target = request.getParameter("TARGET");
        
        // Map the Resource URL into an <Application>
        String applicationId = config.mapRequest(target);
        ApplicationInfo appinfo = config.getApplication(applicationId);
        String handlerURL = request.getRequestURL().toString();
        String providerId = appinfo.getProviderId();
        
        log.debug("Authentication received from "+ipaddr+" for "+target+
                "(application:"+applicationId+") (Provider:"+providerId+")");

        try {
            NewSessionData data = new NewSessionData();
            FilterUtil.sessionDataFromRequest(data,request);
            data.applicationId = applicationId;
            data.handlerURL = handlerURL;
            data.providerId = providerId;
            
            String sessionId = createSessionFromData(data);
            
            // A cookie could be written here, but the browser
            // never comes back to the SP except with an assertion
            // and that produces a new session
//            String cookiename = COOKIEPREFIX+applicationId;
//            Cookie cookie = new Cookie(cookiename,sessionId);
//            response.addCookie(cookie);
            
            /*
             * Now Redirect the Browser
             */
            try {
				if (target.equals("SendAttributesBackToMe")) {
                    // A diagnostic and maybe an API feature. Return the Attributes back to their owner.
					ServletOutputStream outputStream = response.getOutputStream();
					response.setContentType("text/xml");
					Session session = context.getSessionManager().findSession(sessionId,applicationId);
					SAMLResponse attributeResponse = session.getAttributeResponse();
					outputStream.print(attributeResponse.toString());
				} else {
                    if (target.indexOf(':')>0) {
                        // Ordinary URL target. Should not occur any more
                        if (target.indexOf('?')>0)
                            response.sendRedirect(target+"&"+SESSIONPARM+"="+sessionId);
                        else
                            response.sendRedirect(target+"?"+SESSIONPARM+"="+sessionId);
                    } else {
                        // Assume Target is SessionID of 
                        Session session =context.getSessionManager().findSession(sessionId, applicationId);
                        if (session!=null) {
                            String savedTarget = session.getSavedTargetURL();
                            if (savedTarget!=null)
                                target=savedTarget;
                        }
                        response.sendRedirect(target);
                    }
				}
            } catch (IOException e) {
                // The Browser is gone
            }
        }
        catch (MetadataException e) {
            log.error("Authentication Assertion source not found in Metadata.");
            try {
                String msg = appinfo.getErrorsConfig().getMetadata();
                if (msg==null)
                    msg=appinfo.getErrorsConfig().getSession();
                if (msg==null)
                    msg=appinfo.getErrorsConfig().getShire();
                if (msg==null)
                    msg="sessionError.html";
                if (msg.charAt(0)!='/')
                    msg=contextPath+"/"+msg;
                response.sendRedirect(msg);
            } catch (IOException e1) {
                // Browser is gone
            }
        }
        catch (SAMLException e) {
            log.error("Authentication Assertion had invalid format.");
            try {
                String msg = appinfo.getErrorsConfig().getSession();
                if (msg==null)
                    msg=appinfo.getErrorsConfig().getShire();
                if (msg==null)
                    msg="sessionError.html";
                if (msg.charAt(0)!='/')
                    msg=contextPath+"/"+msg;
                response.sendRedirect(msg);
            } catch (IOException e1) {
                // Browser is gone
            }
        }
        finally {
            // Detach ThreadLocal tracking block from the request thread
            // before returning to Web Server.
            ServletContextInitializer.finishService(request,response);
        }
	}
	
    /**
     * NewSessionData is created from the HttpServletRequest and
     * the SPConfig/Application. It can be POSTProfile or Artifact.
     * Create a Session object from it.
     * 
     * <p>Note: This method can also be called from FilterSupport.</p>
     * 
     * @return random key of Session
     * @throws SAMLException
     */
    public static 
    String createSessionFromData(
            NewSessionData data 
            ) 
    throws SAMLException {
        String sessionid=null;
        StringBuffer pproviderId = // Get back IdP Entity name from SAML
            new StringBuffer();
        ServiceProviderConfig config = context.getServiceProviderConfig();
        ApplicationInfo appinfo = config.getApplication(data.applicationId);
        String[] audienceArray = appinfo.getAudienceArray();
        String providerId = appinfo.getProviderId();
        
        // Set up Shibboleth layer to support SAML BrowserProfile
        ShibBrowserProfile profile = new ShibBrowserProfile(data.applicationId);
        
        // Create the Artifact processing Callback (that maps an Artifact
        // to the IdP Artifact resolver endpoint) just in case it is needed
        SPArtifactMapper mapper = new SPArtifactMapper(appinfo,config);
        
        // Build the SAML object that represents data extracted
        // from the FORM or QueryString parameters on the request.
        BrowserProfileRequest bpr = new BrowserProfileRequest();
        bpr.SAMLArt = data.SAMLArt;
        bpr.SAMLResponse = data.SAMLResponse;
        
        bpr.TARGET = data.target;
        
        // Process the encoded SAMLResponse or, if Artifact, fetch
        // a corresponding Response from the IdP.
        BrowserProfileResponse samldata = profile.receive(
                pproviderId,
                bpr,
                data.handlerURL,    
                context.getReplayCache(),
                mapper,
                1
        );
        
        // Check Assertions for restrictions
        Iterator conditions = samldata.assertion.getConditions();
        while (conditions.hasNext()) {
            SAMLCondition cond =
                (SAMLCondition)conditions.next();
            
            if (cond instanceof SAMLAudienceRestrictionCondition) {
                SAMLAudienceRestrictionCondition audienceCondition =
                    (SAMLAudienceRestrictionCondition) cond;
                Iterator audiences = audienceCondition.getAudiences();
                if (audiences==null)
                    continue; // probably invalid
                boolean matched = false;
                StringBuffer audienceTests = new StringBuffer();
                while (!matched && audiences.hasNext()) {
                    String audienceString = (String) audiences.next();
                    audienceTests.append(audienceString);
                    audienceTests.append(' ');
                    if (audienceString.equals(providerId)) {
                        matched=true;
                    }
                    if (audienceArray!=null) {
                        for (int i=0;i<audienceArray.length;i++) {
                            if (audienceString.equals(audienceArray[i])) {
                                matched=true;
                                break;
                            }
                        }
                    }
                }
                if (!matched) {
                    log.error("Assertion restricted to "+audienceTests.toString());
                    StringBuffer audienceBuffer = new StringBuffer("Did not match ");
                    audienceBuffer.append(providerId);
                    if (audienceArray!=null && audienceArray.length>0) {
                        audienceBuffer.append(" or ");
                        for (int i=0;i<audienceArray.length;i++) {
                            audienceBuffer.append(audienceArray[i]);
                            audienceBuffer.append(' ');
                        }
                    }
                    log.error(audienceBuffer.toString());
                    throw new SAMLException("Assertion failed audience restriction test.");
                }
            }
        }

        // Create a new Session object or fill in an existing emtpy
        // Session object with the values from this Assertion.
        SessionManager sessionManager = context.getSessionManager();
        String emptySessionId = null;
        if (data.target.indexOf(':')==-1) {
            // The Target can be a URL or an Empty SessionId
            emptySessionId = data.target;
        }
        sessionid = sessionManager.newSession(
                data.applicationId, 
                data.ipaddr, 
                pproviderId.toString(), 
                samldata.assertion, 
                samldata.authnStatement,
                emptySessionId);
        
        Session session = sessionManager.findSession(sessionid, data.applicationId);
        
        // Fetch attributes immediately (unless we already have them)
        checkForAttributePush(samldata, session);
        AttributeRequestor.fetchAttributes(session);

        return sessionid;
    }


    /**
     * Scan the POST data for Attribute Assertions. If any are found,
     * then attributes have been pushed and we don't need to go to 
     * the AA to get them. 
     * @param samldata The BrowserProfileResponse containing the SAMLResponse
     * @param session The Session just created
     */
    private static void checkForAttributePush(BrowserProfileResponse samldata, Session session) {
        SAMLResponse samlresponse = samldata.response;
        Iterator assertions = samlresponse.getAssertions();
        while (assertions.hasNext()) {
            SAMLAssertion assertion = (SAMLAssertion) assertions.next();
            Iterator statements = assertion.getStatements();
            while (statements.hasNext()) {
                SAMLStatement statement = (SAMLStatement) statements.next();
                if (statement instanceof SAMLAttributeStatement) {
                    log.info("Found Attributes with Authenticaiton data (Attribute Push).");
                    session.setAttributeResponse(samlresponse);
                    // Note, the Attribute Statements have not been checked for 
                    // AAP or Signatures. AttributeRequestor will bypass calling
                    // the AA and will reprocess the POST Response for Attributes.
                    return;
                }
            }
        }
    }


    /**
     * The Artifact comes in a GET. However, the code for processing 
     * the HttpServletRequest is the same for both methods.
     */
    protected void doGet(HttpServletRequest arg0, HttpServletResponse arg1)
    	throws ServletException, IOException {
        log.debug("Received GET: "+ arg0.getQueryString());
    	doPost(arg0,arg1);
    }
	

}
