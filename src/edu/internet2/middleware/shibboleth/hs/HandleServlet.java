package edu.internet2.middleware.shibboleth.hs

import java.io.*;
import java.text.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import edu.internet2.middleware.shibboleth.*;
import edu.internet2.middleware.shibboleth.common.*;
import org.opensaml.*;

public class HandleServlet extends HttpServlet {

    private HandleRepositoryFactory hrf;
    private long ticketExp; 
    private HandleServiceSAML hsSAML;

    public void init(ServletConfig conf)
	throws ServletException
    {
	super.init(conf);
	getInitParams();

	try {
	    hsSAML = new HandleServiceSAML( getInitParameter("domain"), 
					    getInitParameter("AAurl"),
					    getInitParameter("issuer") );
	    hrf = HandleRepositoryFactory.getInstance
		( Constants.POLICY_CLUBSHIB, this );
	}
	catch (SAMLException ex) {
	    throw new ServletException( "Error initializing SAML libraries: " + ex );
	}
	catch (HandleException ex) {
	    throw new ServletException( "Error initializing Handle Service: " +ex );
	}
	if (hsSAML == null) {
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
	    hrf.insertHandleEntry( he );
	    
	    byte[] buf = hsSAML.prepare
		( he.getHandle(), req.getParameter("shire"), 
		  req.getRemoteAddr(), he.getAuthType(), 
		  new Date(he.getAuthInstant()));

	    createForm( req, res, buf );
	}
	catch (HandleException ex) {
	    handleError( req, res, ex );
	}

    }
    
    private void createForm( HttpServletRequest req, 
			     HttpServletResponse res,
			     byte[] buf )  
	throws HandleException {
	try {

	    res.setContentType("text/html");
	    PrintWriter out = res.getWriter();
	    out.println("<HTML><HEAD><TITLE>Handle Service</TITLE></HEAD>");
	    out.println("<BODY onLoad=\"document.forms[0].submit()\">");
	    out.println("<p><form name=\"shib\" " + "action=\"" +
			req.getParameter("shire")+"\" method=\"POST\">");
	    out.println("<input type=\"hidden\" name=\"TARGET\"" +
			" value=\"" + req.getParameter("target") + "\">");
	    out.println("<input type=\"hidden\" name=\"SAMLAssertion\""+
			"value=\"" + buf + "\">");
	    out.println("<input type=\"submit\" value=\"Transmit\">");
	    out.println("</form>");
	    
	    /**
	     * soon to implement forwarding to hs.jsp for submission
             * 
	    //Hardcoded to ASCII to ensure Base64 encoding compatibility
	    req.setAttribute("assertion", new String(buf, "ASCII"));
	    RequestDispatcher rd = req.getRequestDispatcher("/hs.jsp");
	    rd.forward(req, res);
	    */
	} catch (IOException ex) {
	    throw new HandleException
		("IO interruption while displaying Handle Service UI." + ex);
	} 
	/*
	  catch (ServletException ex) {
	    throw new HandleException
		("Problem displaying Handle Service UI." + ex);
	}
	*/
    }

    private void handleError( HttpServletRequest req, 
			     HttpServletResponse res,
			     Exception e )  
	throws ServletException, IOException {

	req.setAttribute("errorText", e.toString());
	//	req.setAttribute("requestURL", req.getRequestURL().toString());
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
}
    

