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
import edu.internet2.middleware.eduPerson.*;




public class AAServlet extends HttpServlet {

    String myName;
    String dirUrl;
    String uidSyntax;
    String arpFactoryMethod;
    String arpFactoryData;
    String ctxFactory;
    AAResponder responder;
    //HandleRepositoryFactory hrf;
    ArpFactory arpFactory;
    
    
    public void init(ServletConfig conf)
	throws ServletException{
	
	try{
	    super.init(conf);
	    myName = getInitParameter("domain");
	    dirUrl = getInitParameter("dirUrl");
	    uidSyntax = getInitParameter("ldapUserDnPhrase");
	    ctxFactory = getInitParameter("ctxFactoryClass");
	    if(ctxFactory == null)
		ctxFactory = "com.sun.jndi.ldap.LdapCtxFactory";
	    arpFactoryMethod = getInitParameter("arpFactoryMethod");
	    arpFactoryData = getInitParameter("arpFactoryData");

	    //hrf = HandleRepositoryFactory.getInstance(Constants.POLICY_CLUBSHIB, this);
	    arpFactory = ArpRepository.getInstance(arpFactoryMethod, arpFactoryData);

	    Hashtable env = new Hashtable(11);
	    env.put(Context.INITIAL_CONTEXT_FACTORY, ctxFactory);

	    env.put(Context.PROVIDER_URL, dirUrl);
	    DirContext ctx = new InitialDirContext(env);
	    
	    responder = new AAResponder(/*hrf*/ null, arpFactory, ctx, myName);
	    //	}catch(HandleException he){
	    //	    throw new ServletException("Init failed: "+he);
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
	    saml = new AASaml(req, myName);
	    String resource = saml.getResource();
	    String handle = saml.getHandle();
	    String shar = saml.getShar();
	    String issuedBy = saml.getIssuer();
	    System.err.println("AA debug: handle:"+handle);
	    System.err.println("AA debug: issuer:"+issuedBy);
	    System.err.println("AA debug: shar:"+shar);

	    attrs = responder.getReleaseAttributes(uidSyntax, handle, shar, resource);
	    System.err.println("AA debug: got attributes");

 	}catch (org.opensaml.SAMLException se) {
	    ourSE = se;
	    //	}catch (HandleException he) {
	    //	    ourSE = new org.opensaml.SAMLException(org.opensaml.SAMLException.RESPONDER,"Bad Handle or Handle Service Problem: "+he);
	}catch (Exception e) {
	    ourSE = new org.opensaml.SAMLException(org.opensaml.SAMLException.RESPONDER,"AA Failed with: "+e);
	}finally{

	    if(saml == null)
		throw new ServletException("AA failed to build a request: "+ourSE);
	    saml.respond(resp, attrs, ourSE);
	}
    }

}
