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

package edu.internet2.middleware.shibboleth.ui;


import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import javax.naming.*;
import javax.naming.directory.*;
import org.apache.log4j.Logger;
import edu.internet2.middleware.shibboleth.aa.*;

public class UI extends HttpServlet {

    private String adminArpName = "admin";
    private String debug = "true";

    private String arpDir;
    private String ldapUrl;
    private String attrFile;

    AAResponder responder;
    ArpRepository arpFactory;
    Arp adminArp;

    private static Logger log = 
	Logger.getLogger(UI.class.getName());; 
    
    public void init(ServletConfig conf)
	throws ServletException
    {
	super.init(conf);
	getInitParams();
	log.info("UI: Loading init params");
	try {
	    Properties props = new Properties();
	    props.setProperty("arpFactoryRealpath", arpDir);
	    arpFactory = ArpRepositoryFactory.getInstance("edu.internet2.middleware.shibboleth.aa.FileArpRepository", props);
	    adminArp = arpFactory.lookupArp("adminArpName", true);
	    if(adminArp ==  null) {
		log.error("Admin ARP not found in Arp Repository (" + arpFactory + ").");
		throw new ServletException("Unable to load admin ARP.");
	    }
	    responder = new AAResponder(arpFactory, getDirCtx(), 
					getInitParameter("domain"));
	} catch (Exception ex) {
	    throw new ServletException(ex);
	}
    }
    
    private void getInitParams() throws ServletException {
	arpDir = getInitParameter("ARPdir");
	if (arpDir == null || arpDir.equals("")) 
	    throw new ServletException("Cannot find location of ARPs in init parameters");

	ldapUrl = getInitParameter("LDAPurl");
	if (ldapUrl == null || ldapUrl.equals("")) 
	    throw new ServletException("Cannot find URL of LDAP directory in init parameters");
	
	attrFile = getInitParameter("AttrJarfile");
	if (attrFile == null || attrFile.equals("")) 
	    throw new ServletException("Cannot find location of attribute jarfile in init parameters");
    }

    public void service(HttpServletRequest req, 
		      HttpServletResponse res)
	throws ServletException, IOException
    {
	String username = req.getParameter("username");

	req.setAttribute("username", username);
	req.setAttribute("requestURL", req.getRequestURI().toString());
	req.setAttribute("attrFile", attrFile);
	req.setAttribute("ldapUrl", ldapUrl);
	req.setAttribute("responder", responder);

	String action = req.getParameter("Submit");
	String resource = req.getParameter("Resource");
	String err = "";

	try{
	    if (username !=null) {
		try{
		    DirContext userCtx = getUserCtx(username);
		} catch (UIException ex) {
		    err = "Error: No record found for user "+username;
		    username = "";
		}
	    }
	    if (username==null || username.equals("") || action==null) {
		getLogin(req, res, err); 
	    }
	    else {
	    if (action.equals("Change user")) {
		getLogin(req, res, err); 
	    }
	    if (action.equals("Login") || action.equals("Cancel")) {
		String isNew = req.getParameter("isNew");
		if (isNew!=null && isNew.equals("true"))
		    deleteArp(username, resource);
		listArps(username, req, res);
	    }
	    if (action.equals("Edit")) {
		editArp(username, resource, req, res, "false");
	    }
	    if (action.equals("Add new resource") || action.equals("Copy")) {
		editArp(username, resource, req, res, "true");
	    }
	    if (action.equals("Save")) {
		saveArp(username, resource, req, res);
	    }
	    if (action.equals("Delete") || action.equals("Delete entire ARP")) {
		deleteArp(username, resource);
		listArps(username, req, res);
	    }
	    if (action.equals("Filter")) {
		editFilter(username, resource, req, res, "false");
	    }
	    if (action.equals("Save Filter")) {
		saveFilter(username, resource, req, res);
	    }
	      }	    
        } catch (UIException ex) {
	    //		System.out.println(ex);
		handleError(req, res, ex);
	    }
    }

    private void loadJsp(String page, 
			 HttpServletRequest req, 
			 HttpServletResponse res)
	throws UIException 
    {
	try { 
	    RequestDispatcher rd = req.getRequestDispatcher(page);
	    rd.forward(req, res);
	} catch (IOException ex) {
	    throw new UIException
		("IO interruption while displaying UI login." + ex);
	} catch (ServletException ex) {
	    throw new UIException
		("Error displaying UI login." + ex);
	} 
    }

    private void getLogin(HttpServletRequest req, 
			 HttpServletResponse res,
			  String err) 
	throws UIException
    {
	req.setAttribute("err", err);
	req.setAttribute("debug", debug);
	loadJsp("/UIlogin.jsp", req, res);
    }

    private void listArps(String username, HttpServletRequest req, 
			  HttpServletResponse res) 
	throws UIException
    {
	try{
	    Arp arp = arpFactory.lookupArp(username, false);
	    req.setAttribute("shars", arp.getShars());
	    req.setAttribute("adminArp", adminArp);
	    req.setAttribute("debug", debug);
	    req.setAttribute("userCtx", getUserCtx(username));
	} catch (Exception ex) {
	    throw new UIException("Error retrieving user" +ex);
	}

	loadJsp("/UIlist.jsp", req, res);
    } 
    

    private void editArp(String username,
			 String resource,
			 HttpServletRequest req, 
			 HttpServletResponse res,
			 String isNew) 
	throws UIException
    {
	try{
	Arp arp = arpFactory.lookupArp(username, false);
	ArpShar s = arp.getShar(resource);

	AAAttributes aaa = new AAAttributes(attrFile);

	req.setAttribute("adminArp", adminArp);
	req.setAttribute("userCtx", getUserCtx(username));
	req.setAttribute("allAttrs", aaa.list());
	req.setAttribute("resource", (s==null) ? new ArpResource("", "") : s.getResource(resource));
	req.setAttribute("isNew", isNew);

	} catch (Exception ex) {
	    throw new UIException("Error retrieving filter." +ex);
	}

	loadJsp("/UIedit.jsp", req, res);
    }

    /*********
     ** Loads page to edit ARP filter 
     **/

    private void editFilter(String username,
			    String resource,
			    HttpServletRequest req, 
			    HttpServletResponse res,
			    String close)
	throws UIException
    {
	try{
	String attr = req.getParameter("Attr");
	Arp arp = arpFactory.lookupArp(username, false);
	ArpShar s = arp.getShar(resource);
	ArpResource r = null;
	ArpAttribute a = null;
	if (s!=null)
	    r = s.getResource(resource);
	if (r!=null)
	    a = r.getAttribute(attr);
	if (a == null)
	    a = new ArpAttribute(attr, false);

	req.setAttribute("userCtx", getUserCtx(username));
	req.setAttribute("resource", resource);
	req.setAttribute("attr", new ArpAttribute(attr, false));
	req.setAttribute("userAttr", a);
	req.setAttribute("close", close);
	} catch (Exception ex) {
	    throw new UIException("Error retrieving filter." +ex);
	}
	loadJsp("/UIfilter.jsp", req, res);
    }

    private DirContext getDirCtx() 
	throws UIException
    {
	DirContext ctx = null;
	Hashtable env = new Hashtable(11);
	env.put(Context.INITIAL_CONTEXT_FACTORY,
		"com.sun.jndi.ldap.LdapCtxFactory");
	env.put(Context.PROVIDER_URL, ldapUrl);
	try { 
	    ctx = new InitialDirContext(env);
	} catch (Exception ex) {
	    throw new UIException
		("Error getting context. "+ex);
	}
	return ctx;
    }
    private DirContext getUserCtx(String username) 
	throws UIException
    {
	DirContext userCtx = null;
	try { 
	    DirContext ctx = getDirCtx();
	    userCtx = (DirContext)ctx.lookup("uid="+username);
	} catch (Exception ex) {
	    throw new UIException
		("Error getting user context for "+username+". "+ex);
	}
	return userCtx;
    }


    private void handleError( HttpServletRequest req, 
			     HttpServletResponse res,
			     Exception e )  
	throws ServletException, IOException {

	req.setAttribute("errorText", e.toString());
	req.setAttribute("requestURL", req.getRequestURI().toString());
	RequestDispatcher rd = req.getRequestDispatcher("/UIerror.jsp");
	
	rd.forward(req, res);
	
    }
	   
    private void deleteArp(String username, String resource)
    {
	try{ 
	    Arp arp = arpFactory.lookupArp(username, false);
	    if (arp.isNew())
		return;
	    if (resource==null || resource.equals("")) {
		arpFactory.remove(arp);
		return;
	    }
	    /* NOTE: at the time of this interface, SHAR was required for 
	       sorting but, was not being specified by the user, so the 
	       resource and shar are the same thing. Thus, to delete a 
	       resource, delete both resource and shar.  If these two 
	       concepts get separated out again, do it individually */
	    ArpShar s = arp.getShar(resource);
	    if (s==null) 
		return;
	    ArpResource r = s.getResource(resource);
	    if (r==null)
		return;
	    s.removeAResource(resource);
	    arp.removeAShar(resource);
	    arpFactory.update(arp);
	} catch (Exception e)  {
	}
    }

    private void saveArp(String username, 
			 String resource,
			 HttpServletRequest req,
			 HttpServletResponse res)
    {
	try{ 
	    Arp arp = arpFactory.lookupArp(username, false);
	    String []subAttrs = req.getParameterValues("attr");
	    ArpShar s = arp.getShar(resource);
	    if (s==null) 
		s = new ArpShar(resource, false); 
	    ArpResource r = s.getResource(resource);
	    if (r==null)
		r = new ArpResource(resource);
	    ArpAttribute[] attrs = r.getAttributes();

	    ArpResource nr = new ArpResource(resource, req.getParameter("comment"));
	    if (subAttrs!=null){
		for (int i = 0; i < subAttrs.length; i++) {
		    ArpAttribute a = r.getAttribute(subAttrs[i]);
		    if (a!=null) 
			nr.addAnAttribute(a);
		    else {
			a = new ArpAttribute(subAttrs[i], false);
			nr.addAnAttribute(a);
		    }
		}
	    }
	    s.addAResource(nr, true);
	    arp.addAShar(s);
	    arpFactory.update(arp);

	    listArps(username, req, res);

	} catch (Exception e)  {
	}
    }

    private void saveFilter(String username, 
			    String resource,
			    HttpServletRequest req,
			    HttpServletResponse res)
	throws UIException
    {
	try{
	String attr = req.getParameter("Attr");
	Arp arp = arpFactory.lookupArp(username, false);
	ArpShar s = arp.getShar(resource);
	if (s==null)
	    s = new ArpShar(resource, false);
	ArpResource r = s.getResource(resource);
	if (r==null)
	    r = new ArpResource(resource);
	ArpAttribute a = r.getAttribute(attr);
	if (a==null)
	    a = new ArpAttribute(attr, false);
	
	ArpFilter filter = new ArpFilter();

	String[] vals = req.getParameterValues("filterval");
	if (vals!=null){
	    for (int i=0; i<vals.length; i++) {
		ArpFilterValue afv = new ArpFilterValue(vals[i], false);
		filter.addAFilterValue(afv, true);
	    }
	}
	a.setFilter(filter, true);
	r.addAnAttribute(a);
	s.addAResource(r);
	arp.addAShar(s);
	arpFactory.update(arp);

	editFilter(username, resource, req, res, "true");

	} catch (Exception ex) {
	    System.err.println("error: " +ex);
	}

    }

}
