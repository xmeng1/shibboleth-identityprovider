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

	    ServletConfig sc = getServletConfig();
	    ServletContext sctx = sc.getServletContext(); 
	    hrf = (HandleRepositoryFactory)sctx.getAttribute("HandleRepository");
      
	    arpFactory = ArpRepository.getInstance(arpFactoryMethod, arpFactoryData);

	    Hashtable env = new Hashtable(11);
	    env.put(Context.INITIAL_CONTEXT_FACTORY, ctxFactory);

	    env.put(Context.PROVIDER_URL, dirUrl);
	    DirContext ctx = new InitialDirContext(env);
	    
	    responder = new AAResponder(hrf, arpFactory, ctx, myName);

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

	try{
	    System.out.println("AA about to make a saml obj");
	    saml = new AASaml(myName);
	    saml.receive(req);
	    System.out.println("AA received a query");
	    String resource = saml.getResource();
	    String handle = saml.getHandle();
	    String shar = saml.getShar();
	    String issuedBy = saml.getIssuer();
	    System.err.println("AA debug: handle:"+handle);
	    System.err.println("AA debug: issuer:"+issuedBy);
	    System.err.println("AA debug: shar:"+shar);

	    attrs = responder.getReleaseAttributes(uidSyntax, handle, shar, resource);
	    System.err.println("AA debug: got attributes");
	    saml.respond(resp, attrs, null);

 	}catch (org.opensaml.SAMLException se) {
	    try{
		saml.fail(resp, new SAMLException(null, "AA got a SAML Exception: "+se));
	    }catch(Exception ee){
		throw new ServletException("AA failed to even make a SAML Failure message because "+ee+"  Origianl problem: "+se);
	    }
	    //	}catch (HandleException he) {
	    //	    ourSE = new org.opensaml.SAMLException(org.opensaml.SAMLException.RESPONDER,"Bad Handle or Handle Service Problem: "+he);
	}catch (Exception e) {
	    try{
		saml.fail(resp, new SAMLException(null, "AA got an Exception: "+e));
	    }catch(Exception ee){
		throw new ServletException("AA failed to even make a SAML Failure message because "+ee+"  Origianl problem: "+e);
	    }

	}
    }

}
