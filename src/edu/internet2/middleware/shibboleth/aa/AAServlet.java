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
import edu.internet2.middleware.shibboleth.hs.*;
import edu.internet2.middleware.eduPerson.*;
import org.apache.log4j.Logger;



public class AAServlet extends HttpServlet {

    String myName;
    String dirUrl;
    String uidSyntax;
    String arpFactoryMethod;
    String arpFactoryData;
    String ctxFactory;
    AAResponder responder;
    HandleRepositoryFactory hrf;
    ArpFactory arpFactory;
    private static Logger log = Logger.getLogger(AAServlet.class.getName());    
    
    public void init(ServletConfig conf)
	throws ServletException{
	
	try{
	    super.init(conf);
	    edu.internet2.middleware.eduPerson.Init.init();
	    myName = getInitParameter("domain");
	    dirUrl = getInitParameter("dirUrl");
	    uidSyntax = getInitParameter("ldapUserDnPhrase");
	    ctxFactory = getInitParameter("ctxFactoryClass");
	    if(ctxFactory == null)
		ctxFactory = "com.sun.jndi.ldap.LdapCtxFactory";
	    arpFactoryMethod = getInitParameter("arpFactoryMethod");
	    arpFactoryData = getInitParameter("arpFactoryData");


      
	    arpFactory = ArpRepository.getInstance(arpFactoryMethod, arpFactoryData);

	    Hashtable env = new Hashtable(11);
	    env.put(Context.INITIAL_CONTEXT_FACTORY, ctxFactory);

	    env.put(Context.PROVIDER_URL, dirUrl);
	    DirContext ctx = new InitialDirContext(env);
	    
	    responder = new AAResponder(arpFactory, ctx, myName);
	    log.info("AA all initialized at "+new Date());

	}catch(NamingException ne){
	    throw new ServletException("Init failed: "+ne);
	}catch(AAException ae){
	    throw new ServletException("Init failed: "+ae);
	}
    }

    public void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        resp.setContentType("text/html");
        PrintWriter out = resp.getWriter();
	out.println("<HTML><BODY> Sorry! GET is not supported. </BODY></HTML>");
	return;
    }
	
    public void doPost(HttpServletRequest req, HttpServletResponse resp)
        throws ServletException, IOException {

	SAMLAttribute[] attrs = null;
	SAMLException ourSE = null;
	AASaml saml = null;
	String userName = null;
	    
	try{
	    saml = new AASaml(myName);
	    saml.receive(req);
	    log.info("AA received a query");
	    String resource = saml.getResource();
	    String handle = saml.getHandle();
	    String shar = saml.getShar();
	    String issuedBy = saml.getIssuer();
	    log.info("AA: handle:"+handle);
	    log.info("AA: issuer:"+issuedBy);
	    log.info("AA: shar:"+shar);

	    // get HS and convert handle to userName
	    ServletConfig sc = getServletConfig();
	    ServletContext sctx = sc.getServletContext(); 
	    hrf = (HandleRepositoryFactory)sctx.getAttribute("HandleRepository");
	    log.debug("Context aTTR: "+sctx.getAttribute("HandleRepository"));

	    if(handle.equalsIgnoreCase("foo")){
		// for testing only
		userName = "dousti"; 
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

}
