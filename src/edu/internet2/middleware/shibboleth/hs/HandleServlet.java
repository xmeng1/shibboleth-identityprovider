/* 
 * The Shibboleth License, Version 1. 
 * Copyright (c) 2002 
 * University Corporation for Advanced Internet Development, Inc. 
 * All rights reserved
 * 
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this 
 * list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, 
 * this list of conditions and the following disclaimer in the documentation 
 * and/or other materials provided with the distribution, if any, must include 
 * the following acknowledgment: "This product includes software developed by 
 * the University Corporation for Advanced Internet Development 
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement 
 * may appear in the software itself, if and wherever such third-party 
 * acknowledgments normally appear.
 * 
 * Neither the name of Shibboleth nor the names of its contributors, nor 
 * Internet2, nor the University Corporation for Advanced Internet Development, 
 * Inc., nor UCAID may be used to endorse or promote products derived from this 
 * software without specific prior written permission. For written permission, 
 * please contact shibboleth@shibboleth.org
 * 
 * Products derived from this software may not be called Shibboleth, Internet2, 
 * UCAID, or the University Corporation for Advanced Internet Development, nor 
 * may Shibboleth appear in their name, without prior written permission of the 
 * University Corporation for Advanced Internet Development.
 * 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK 
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE. 
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY 
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT, 
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.hs;

import java.io.*;
import java.text.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import edu.internet2.middleware.shibboleth.common.*;
import org.opensaml.*;
import sun.misc.BASE64Decoder;
import org.apache.log4j.Logger;

public class HandleServlet extends HttpServlet {

    private HandleRepositoryFactory hrf;
    private long ticketExp; 
    private String username=null;
    private HandleServiceSAML hsSAML;
    private String rep;
    private static Logger log = Logger.getLogger(HandleServlet.class.getName());; 

    public void init(ServletConfig conf)
	throws ServletException
    {
	super.init(conf);
	ServletConfig sc = getServletConfig();
	ServletContext sctx = sc.getServletContext();

	getInitParams();
	log.info("HS: Loading init params");

	try {
	    edu.internet2.middleware.eduPerson.Init.init();
	    InputStream is = sctx.getResourceAsStream(getInitParameter("KSpath"));
	    hsSAML = new HandleServiceSAML( getInitParameter("domain"), 
					    getInitParameter("AAurl"),
					    getInitParameter("HSname"),
					    getInitParameter("KSpass"),
					    getInitParameter("KSkeyalias"),
					    getInitParameter("KSkeypass"),
					    getInitParameter("certalias"),
					    is );
	    
	    log.info("HS: Initializing Handle Repository with "+rep+" repository type.");
	    hrf = getHandleRepository();
	}
	catch (SAMLException ex) {
	    log.fatal("Error initializing SAML libraries: "+ ex);
	    throw new ServletException( "Error initializing SAML libraries: " + ex );
	}
	catch (java.security.KeyStoreException ex) {
	    log.fatal("Error initializing private KeyStore: "+ex);
	    throw new ServletException( "Error initializing private KeyStore: " + ex );
	}
	catch (RuntimeException ex) {
	    log.fatal("Error initializing eduPerson.Init: "+ ex); 
	    throw new ServletException( "Error initializing eduPerson.Init: "+ ex); 
	}
	catch (HandleException ex) {
	    log.fatal("Error initializing Handle Service: " +ex );
	    throw new ServletException( "Error initializing Handle Service: " +ex );
	}
	catch (Exception ex) {
	    log.fatal("Error in initialization: " +ex );
	    throw new ServletException( "Error in initialization: " +ex );
	}

	if (hsSAML == null) {
	    log.fatal("Error initializing SAML libraries: No Profile created." );
	    throw new ServletException( "Error initializing SAML libraries: No Profile created." );
	}  

    }


    private void getInitParams() throws ServletException {

	String ticket = getInitParameter("ticket");
	if (ticket == null) {
	    ticket = "1400000";
	}
	ticketExp = Long.parseLong(ticket);

	username=getInitParameter("username");

	if ( getInitParameter("domain") == null || 
	     getInitParameter("domain").equals("")) {
	    throw new ServletException("Cannot find host domain in init parameters");
	}
	if ( getInitParameter("AAurl") == null || 
	     getInitParameter("AAurl").equals("")) {
	    throw new ServletException("Cannot find host Attribute Authority location in init parameters");
	}
	if ( getInitParameter("HSname") == null || 
	     getInitParameter("HSname").equals("")) {
	    throw new ServletException("Cannot find Handle Service name in init parameters");
	}
	if ( getInitParameter("KSpath") == null || 
	     getInitParameter("KSpath").equals("")) {
	    throw new ServletException("Cannot find path to KeyStore file in init parameters");
	}
	if ( getInitParameter("KSpass") == null || 
	     getInitParameter("KSpass").equals("")) {
	    throw new ServletException("Cannot find password to KeyStore in init parameters");
	}
	if ( getInitParameter("KSkeyalias") == null || 
	     getInitParameter("KSkeyalias").equals("")) {
	    throw new ServletException("Cannot find private key alias to KeyStore in init parameters");
	}
	if ( getInitParameter("KSkeypass") == null || 
	     getInitParameter("KSkeypass").equals("")) {
	    throw new ServletException("Cannot find private key password to Keystore in init parameters");
	}
	if ( getInitParameter("certalias") == null || 
	     getInitParameter("certalias").equals("")) {
	    throw new ServletException("Cannot find certificate alias in init parameters");
	}
	rep = getInitParameter("repository");
	if ( rep == null || rep.equals("")) {
	    rep = "MEMORY"; 
	}
    }


    public void doGet(HttpServletRequest req, 
		      HttpServletResponse res)
	throws ServletException, IOException
    {



	HandleEntry he = null;

	try {
	    checkRequestParams(req);

	    req.setAttribute("shire", req.getParameter("shire"));
	    req.setAttribute("target", req.getParameter("target"));

	    he = new HandleEntry(
	        (username==null || username.equalsIgnoreCase("REMOTE_USER")) ? req.getRemoteUser() : req.getHeader(username),
		req.getAuthType(),
		ticketExp );
	    log.info("Issued Handle (" + he.getHandle() + ") to (" + he.getUsername() + ")");
	    hrf.insertHandleEntry( he );
	    
	    byte[] buf = hsSAML.prepare
		( he.getHandle(), req.getParameter("shire"), 
		  req.getRemoteAddr(), he.getAuthType(), 
		  new Date(he.getAuthInstant()));

	    createForm( req, res, buf );
	}
	catch (HandleException ex) {
	    log.error(ex);
	    handleError( req, res, ex );
	}

    }
    
    private void createForm( HttpServletRequest req, 
			     HttpServletResponse res,
			     byte[] buf )  
	throws HandleException
    {
	try {
	    /**
	     * forwarding to hs.jsp for submission
             */
	    //Hardcoded to ASCII to ensure Base64 encoding compatibility
	    req.setAttribute("assertion", new String(buf, "ASCII"));
	    
	    if (log.isDebugEnabled()) {
				try {
					log.debug(
						"Dumping generated SAML Response:"
							+ System.getProperty("line.separator")
							+ new String(
								new BASE64Decoder().decodeBuffer(new String(buf, "ASCII")),
								"UTF8"));
				} catch (IOException e) {
					log.error("Encountered an error while decoding SAMLReponse for logging purposes.");
				}
			}
	    
	    
	    RequestDispatcher rd = req.getRequestDispatcher("/hs.jsp");
	    rd.forward(req, res);
	    
	} catch (IOException ex) {
	    throw new HandleException
		("IO interruption while displaying Handle Service UI." + ex);
	} 
	
	  catch (ServletException ex) {
	    throw new HandleException
		("Problem displaying Handle Service UI." + ex);
	}

    }

    private void handleError( HttpServletRequest req, 
			     HttpServletResponse res,
			     Exception e )  
	throws ServletException, IOException {

	req.setAttribute("errorText", e.toString());
	req.setAttribute("requestURL", req.getRequestURI().toString());
	RequestDispatcher rd = req.getRequestDispatcher("/hserror.jsp");
	
	rd.forward(req, res);
	
    }

		     
    private void checkRequestParams( HttpServletRequest req )
	throws HandleException {

	if ( req.getParameter("target") == null 
	     || req.getParameter("target").equals("")) {
	    throw new HandleException("Invalid data from SHIRE: no target URL received.");
	}
	if ((req.getParameter("shire") == null)
	    || (req.getParameter("shire").equals(""))) {
	    throw new HandleException("Invalid data from SHIRE: No acceptance URL received.");
	}
	if ((req.getRemoteUser() == null)
	    || (req.getRemoteUser().equals(""))) {
	    throw new HandleException("Unable to authenticate remote user");
	}
	if ((req.getAuthType() == null) || (req.getAuthType().equals(""))) {
	    throw new HandleException("Unable to obtain authentication type of user.");
	}
	if ((req.getRemoteAddr() == null)
	    || (req.getRemoteAddr().equals(""))) {
	    throw new HandleException("Unable to obtain client address.");
	}    
    }


    private synchronized HandleRepositoryFactory getHandleRepository()
	throws HandleException{

	ServletConfig sc = getServletConfig();
	ServletContext sctx = sc.getServletContext(); 
	HandleRepositoryFactory hrf = (HandleRepositoryFactory)sctx.getAttribute("HandleRepository");

	log.debug("Context attribute for HandleRepository: "+hrf);
	    
	if(hrf == null){
	    // make one
	    String repositoryType = this.getServletContext().getInitParameter("repository");
	    hrf = HandleRepositoryFactory.getInstance(Constants.POLICY_CLUBSHIB,
						      repositoryType,
						      this );
	    sctx.setAttribute("HandleRepository", hrf);
	    log.info("A new HandleRepository created by HS: "+hrf);
	}
	return hrf;
    }
}

    

