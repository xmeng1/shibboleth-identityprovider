package edu.internet2.middleware.shibboleth.hs;

import java.io.*;
import java.text.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import edu.internet2.middleware.shibboleth.*;
import edu.internet2.middleware.shibboleth.common.*;
import org.opensaml.*;
import org.apache.log4j.Logger;

public class HandleServlet extends HttpServlet {

    private HandleRepositoryFactory hrf;
    private long ticketExp; 
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
	System.err.println("HS: initializing");

	try {
	    edu.internet2.middleware.eduPerson.Init.init();
	    InputStream is = sctx.getResourceAsStream
		(getInitParameter("KSpath"));
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

	sctx.setAttribute("HandleRepository", hrf);
	
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

	    he = new HandleEntry( req.getRemoteUser(), req.getAuthType(), 
				  ticketExp );
	    log.info("HS: Got Handle: "+ he.getHandle());
	    System.err.println("HS: Got Handle: "+ he.getHandle());
	    hrf.insertHandleEntry( he );
	    
	    byte[] buf = hsSAML.prepare
		( he.getHandle(), req.getParameter("shire"), 
		  req.getRemoteAddr(), he.getAuthType(), 
		  new Date(he.getAuthInstant()));

	    createForm( req, res, buf );
	}
	catch (HandleException ex) {
	    System.out.println(ex);
	    handleError( req, res, ex );
	}

    }
    
    private void createForm( HttpServletRequest req, 
			     HttpServletResponse res,
			     byte[] buf )  
	throws HandleException {
	try {

	    /**
	     * forwarding to hs.jsp for submission
             */
	    //Hardcoded to ASCII to ensure Base64 encoding compatibility
	    req.setAttribute("assertion", new String(buf, "ASCII"));
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
	    hrf = HandleRepositoryFactory.getInstance(						      Constants.POLICY_CLUBSHIB, 
												      repositoryType,
												      this );
	}
	return hrf;
    }


}

    

