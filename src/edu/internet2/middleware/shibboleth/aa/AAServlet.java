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

package edu.internet2.middleware.shibboleth.aa;

import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import javax.naming.*;
import javax.naming.directory.*;
import org.opensaml.*;
import org.w3c.dom.*;
import edu.internet2.middleware.shibboleth.*;
import edu.internet2.middleware.shibboleth.common.*;
import edu.internet2.middleware.shibboleth.hs.*;
import edu.internet2.middleware.eduPerson.*;
import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.doomdark.uuid.UUIDGenerator;

/**
 *  Attribute Authority & Release Policy
 *  Handles Initialization and incoming requests to AA
 *
 * @author     Parviz Dousti (dousti@cmu.edu)
 * @created    June, 2002
 */

public class AAServlet extends HttpServlet {

    String myName;
    String dirUrl;
    String uidSyntax;
    String arpFactoryMethod;
    String ctxFactory;
    AAResponder responder;
    HandleRepositoryFactory hrf;
    ArpFactory arpFactory;
    private static Logger log = Logger.getLogger(AAServlet.class.getName());    
    
    public void init()
	throws ServletException{
		
	MDC.put("serviceId", "[AA Core]");
	
	try{

	    edu.internet2.middleware.eduPerson.Init.init();
	    myName = getInitParameter("domain");
	    dirUrl = getInitParameter("dirUrl");
	    uidSyntax = getInitParameter("ldapUserDnPhrase");
	    ctxFactory = getInitParameter("ctxFactoryClass");
	    if(ctxFactory == null)
		ctxFactory = "com.sun.jndi.ldap.LdapCtxFactory";
            // build a properties object to be handed to ArpFactories
            // include all parameters :-(
            Enumeration en = getInitParameterNames();
            Properties props = new Properties();
            while(en.hasMoreElements()){
                String key = (String)en.nextElement();
                String val = getInitParameter(key);
                props.setProperty(key, val);
            }
            props.setProperty("arpFactoryRealPath",
                              getServletContext().getRealPath("/"));

            arpFactoryMethod = getInitParameter("arpFactoryMethod");

   
            arpFactory = ArpRepository.getInstance(arpFactoryMethod, props);

	    log.info("Using "+ctxFactory+" as directory for attributes.");

	    Hashtable env = new Hashtable(11);
	    env.put(Context.INITIAL_CONTEXT_FACTORY, ctxFactory);

	    env.put(Context.PROVIDER_URL, dirUrl);
	    DirContext ctx = new InitialDirContext(env);
	    
	    responder = new AAResponder(arpFactory, ctx, myName);

	    hrf = getHandleRepository();

	    log.info("AA all initialized at "+new Date());

	}catch(NamingException ne){
	    log.fatal("AA init failed: "+ne);
	    throw new ServletException("Init failed: "+ne);
	}catch(AAException ae){
	    log.fatal("AA init failed: "+ae);
	    throw new ServletException("Init failed: "+ae);
	}catch(HandleException he){
	    log.fatal("AA init failed: "+he);
	    throw new ServletException("Init failed: "+he);
	}
    }

    public void doPost(HttpServletRequest req, HttpServletResponse resp)
        throws ServletException, IOException {
        	
	log.info("Recieved a request.");
	MDC.put("serviceId", UUIDGenerator.getInstance().generateRandomBasedUUID());
	MDC.put("remoteAddr", req.getRemoteAddr());
	log.info("Handling request.");

	SAMLAttribute[] attrs = null;
	SAMLException ourSE = null;
	AASaml saml = null;
	String userName = null;
	    
	try{
	    saml = new AASaml(myName);
	    saml.receive(req);
	    String resource = saml.getResource();
	    String handle = saml.getHandle();
	    String shar = saml.getShar();
	    String issuedBy = saml.getIssuer();
	    log.info("AA: handle:"+handle);
	    log.info("AA: issuer:"+issuedBy);
	    log.info("AA: shar:"+shar);


	    if(handle.equalsIgnoreCase("foo")){
		// for testing only
		userName = "dummy"; 
	    }else{
		if(hrf == null){
		    throw new HandleException("No HandleRepository found! Has HS initialized?");
		}else{
		    HandleEntry he = hrf.getHandleEntry(handle);
		    userName = he.getUsername();
		    if(userName == null)
			throw new HandleException("HandleServer returns null for user name!");
		}
	    }

	    attrs = responder.getReleaseAttributes(userName, uidSyntax, handle, shar, resource);
	    log.info("Got "+attrs.length+" attributes for "+userName);
	    saml.respond(resp, attrs, null);
	    log.info("Successfully responded about "+userName);

 	}catch (org.opensaml.SAMLException se) {
	    log.error("AA failed for "+userName+" because of: "+se);
	    try{
		saml.fail(resp, new SAMLException(SAMLException.RESPONDER, "AA got a SAML Exception: "+se));
	    }catch(Exception ee){
		throw new ServletException("AA failed to even make a SAML Failure message because "+ee+"  Origianl problem: "+se);
	    }
	}catch (HandleException he) {
	    log.error("AA failed for "+userName+" because of: "+he);
	    try{
		QName[] codes=new QName[2];
		codes[0]=SAMLException.REQUESTER[0];
		codes[1]=new QName(
				   edu.internet2.middleware.shibboleth.common.XML.SHIB_NS,
				   "InvalidHandle");
		saml.fail(resp, new SAMLException(codes, "AA got a HandleException: "+he));
	    }catch(Exception ee){
		throw new ServletException("AA failed to even make a SAML Failure message because "+ee+"  Origianl problem: "+he);
	    }
	}catch (Exception e) {
	    log.error("AA failed for "+userName+" because of: "+e);
	    try{
		saml.fail(resp, new SAMLException(SAMLException.RESPONDER, "AA got an Exception: "+e));
	    }catch(Exception ee){
		throw new ServletException("AA failed to even make a SAML Failure message because "+ee+"  Origianl problem: "+e);
	    }

	}
    }


    private synchronized HandleRepositoryFactory getHandleRepository()
	throws HandleException, AAException{

	ServletConfig sc = getServletConfig();
	ServletContext sctx = sc.getServletContext(); 
	HandleRepositoryFactory hrf = (HandleRepositoryFactory)sctx.getAttribute("HandleRepository");

	log.debug("Context attribute for HandleRepository: "+hrf);
	    
	    
	if(hrf == null){
	    // make one
	    String repositoryType = this.getServletContext().getInitParameter("repository");
	    if(repositoryType == null)
		throw new AAException("repository parameter not set. Unknown Handle repository type");
	    hrf = HandleRepositoryFactory.getInstance(						      Constants.POLICY_CLUBSHIB, 
												      repositoryType,
												      this );
	    sctx.setAttribute("HandleRepository", hrf);
	    log.info("A new HandleRepository created by AA: "+hrf);
	    
	}
	return hrf;
    }


}
