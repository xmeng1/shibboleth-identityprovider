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

package edu.internet2.middleware.shibboleth.wayf;

import java.io.IOException;
import java.io.InputStream;
import java.net.URLEncoder;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.UnavailableException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.xml.sax.SAXException;

import edu.internet2.middleware.shibboleth.common.ShibResource;

/**
 * A servlet implementation of the Shibboleth WAYF service.  Allows a browser user to 
 * select from among a group of origin sites.  User selection is optionally cached 
 * and the user is forwarded to the HandleService appropriate to his selection.
 *
 * @author Walter Hoehn wassa&#064;columbia.edu
 */
public class WayfService extends HttpServlet {

	private String wayfConfigFileLocation;
	private String siteConfigFileLocation;
	private WayfConfig config;
	private WayfOrigins originConfig;
	private WayfCacheOptions wOptions = new WayfCacheOptions();
	private static Logger log = Logger.getLogger(WayfService.class.getName());

	/**
	 * @see GenericServlet#init()
	 */
	public void init() throws ServletException {

		super.init();
		log.info("Initializing WAYF.");
		loadInitParams();
		log.info("Loading configuration from file.");
		configure();
		
		//Setup Cacheing options
		wOptions.setDomain(config.getCacheDomain());
		wOptions.setExpiration(config.getCacheExpiration());
		
		initViewConfig();
		log.info("WAYF initialization completed.");
	}

	/**
	 * Populates WayfConfig and WayfOrigins objects from file contents.
	 */
	private void configure() throws UnavailableException {
		try {
			InputStream is = new ShibResource(wayfConfigFileLocation, this.getClass()).getInputStream();
			WayfConfigDigester digester = new WayfConfigDigester();
			digester.setValidating(true);
			config = (WayfConfig) digester.parse(is);

		} catch (SAXException se) {
			log.fatal("Error parsing WAYF configuration file.", se);
			throw new UnavailableException("Error parsing WAYF configuration file.");
		} catch (IOException ioe) {
			log.fatal("Error reading WAYF configuration file.", ioe);
			throw new UnavailableException("Error reading WAYF configuration file.");
		}

		try {
			InputStream siteIs = getServletContext().getResourceAsStream(siteConfigFileLocation);
			OriginSitesDigester siteDigester = new OriginSitesDigester();
			siteDigester.setValidating(true);
			originConfig = (WayfOrigins) siteDigester.parse(siteIs);

		} catch (SAXException se) {
			log.fatal("Error parsing site file.", se);
			throw new UnavailableException("Error parsing site file.");
		} catch (IOException ioe) {
			log.fatal("Error reading site file.", ioe);
			throw new UnavailableException("Error reading site file.");
		}
	}
	
	/**
	 * Setup application-wide beans for view
	 */
	private void initViewConfig() {
		getServletContext().setAttribute("originsets", originConfig.getOriginSets());
		getServletContext().setAttribute("supportContact", config.getSupportContact());
		getServletContext().setAttribute("helpText", config.getHelpText());
		getServletContext().setAttribute("searchResultEmptyText", config.getSearchResultEmptyText());
		getServletContext().setAttribute("logoLocation", config.getLogoLocation());
	}

	/**
	 * Reads parameters from web.xml <init-param /> construct.
	 */
	private void loadInitParams() {

		wayfConfigFileLocation = getServletConfig().getInitParameter("WAYFConfigFileLocation");
		if (wayfConfigFileLocation == null) {
			log.warn("No WAYFConfigFileLocation parameter found... using default location.");
			wayfConfigFileLocation = "/conf/wayfconfig.xml";
		}
		siteConfigFileLocation = getServletConfig().getInitParameter("SiteConfigFileLocation");
		if (siteConfigFileLocation == null) {
			log.warn("No SiteonfigFileLocation parameter found... using default location.");
			siteConfigFileLocation = "/sites.xml";
		}

	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest, HttpServletResponse)
	 */
	public void doGet(HttpServletRequest req, HttpServletResponse res) {

		log.info("Handling WAYF request.");
		//Tell the browser not to cache the WAYF page
		res.setHeader("Cache-Control", "no-cache");
		res.setHeader("Pragma", "no-cache");
		res.setDateHeader("Expires", 0);

		//Decide how to route the request based on query string
		String requestType = req.getParameter("action");
		if (requestType == null) {
			requestType = "lookup";
		}
		try {
			if (requestType.equals("deleteFromCache")) {
				log.debug("Deleting saved HS from cache");
				WayfCacheFactory.getInstance(config.getCacheType(), wOptions).deleteHsFromCache(req, res);
				handleLookup(req, res);
			} else if (WayfCacheFactory.getInstance(config.getCacheType()).hasCachedHS(req)) {
				forwardToHS(
					req,
					res,
					WayfCacheFactory.getInstance(config.getCacheType()).getCachedHS(req));
			} else if (requestType.equals("search")) {
				handleSearch(req, res);
			} else if (requestType.equals("selection")) {
				handleSelection(req, res);
			} else {
				handleLookup(req, res);
			}
		} catch (WayfException we) {
			handleError(req, res, we);
		}
	}

	/**
	 * Displays a WAYF selection page.
	 */
	private void handleLookup(HttpServletRequest req, HttpServletResponse res) throws WayfException {

		try {
			if ((getSHIRE(req) == null) || (getTarget(req) == null)) {
				throw new WayfException("Invalid or missing data from SHIRE");
			}
			req.setAttribute("shire", getSHIRE(req));
			req.setAttribute("target", getTarget(req));
			req.setAttribute("encodedShire", URLEncoder.encode(getSHIRE(req), "UTF-8"));
			req.setAttribute("encodedTarget", URLEncoder.encode(getTarget(req), "UTF-8"));
			req.setAttribute("requestURL", req.getRequestURI().toString());

			log.debug("Displaying WAYF selection page.");
			RequestDispatcher rd = req.getRequestDispatcher("/wayf.jsp");

			rd.forward(req, res);
		} catch (IOException ioe) {
			throw new WayfException("Problem displaying WAYF UI." + ioe.toString());
		} catch (ServletException se) {
			throw new WayfException("Problem displaying WAYF UI." + se.toString());
		}
	}
	
	/**
	 * Looks for origin sites that match search terms supplied by the user
	 */
	private void handleSearch(HttpServletRequest req, HttpServletResponse res) throws WayfException {

		if (req.getParameter("string") != null) {
			Origin[] origins = originConfig.seachForMatchingOrigins(req.getParameter("string"), config);
			if (origins.length != 0) {
				req.setAttribute("searchresults", origins);
			} else {
				req.setAttribute("searchResultsEmpty", "true");
			}
		}
		handleLookup(req, res);
	}

	/**
	 * Registers a user's HS selection and forwards appropriately
	 */
	private void handleSelection(HttpServletRequest req, HttpServletResponse res) throws WayfException {

		log.debug("Processing handle selection: " + req.getParameter("origin"));
		String handleService = originConfig.lookupHSbyName(req.getParameter("origin"));
		if (handleService == null) {
			handleLookup(req, res);
		} else {
			if ((req.getParameter("noCache") == null)
				|| !(req.getParameter("noCache").equalsIgnoreCase("TRUE"))) {
				WayfCacheFactory.getInstance(config.getCacheType(), wOptions).addHsToCache(handleService, req, res);
			}
			forwardToHS(req, res, handleService);
		}

	}

	/**
	 * Uses an HTTP Status 307 redirect to forward the user the HS.
	 * @param handleService The URL of the Shiboleth HS.
	 */
	private void forwardToHS(HttpServletRequest req, HttpServletResponse res, String handleService)
		throws WayfException {

		String shire = getSHIRE(req);
		String target = getTarget(req);
		log.info("Redirecting to selected Handle Service");
		try {
			res.sendRedirect(
				handleService
					+ "?target="
					+ URLEncoder.encode(target, "UTF-8")
					+ "&shire="
					+ URLEncoder.encode(shire, "UTF-8"));
		} catch (IOException ioe) {
			throw new WayfException("Error forwarding to HS: " + ioe.toString());
		}

	}

	/**
	 * Handles all "recoverable" errors in WAYF processing by logging the error
	 * and forwarding the user to an appropriate error page.
	 * @param we The WayfException respective to the error being handled
	 */
	private void handleError(HttpServletRequest req, HttpServletResponse res, WayfException we) {

		log.error("WAYF Failure: " + we.toString());
		log.debug("Displaying WAYF error page.");
		req.setAttribute("errorText", we.toString());
		req.setAttribute("requestURL", req.getRequestURI().toString());
		RequestDispatcher rd = req.getRequestDispatcher("/wayferror.jsp");

		try {
			rd.forward(req, res);
		} catch (IOException ioe) {
			log.error("Problem trying to display WAYF error page: " + ioe.toString());
		} catch (ServletException se) {
			log.error("Problem trying to display WAYF error page: " + se.toString());
		}
	}
	/**
	 * Retrieves the SHIRE from the request.
	 * @throws WayfException If the request does not contain a shire parameter.
	 */
	private String getSHIRE(HttpServletRequest req) throws WayfException {

		String shire = (String) req.getAttribute("shire");
		if (req.getParameter("shire") != null) {
			shire = req.getParameter("shire");
		}
		if (shire == null) {
			throw new WayfException("Invalid data from SHIRE: No acceptance URL received.");
		}
		return shire;
	}
	/**
	 * Retrieves the user's target URL from the request.
	 * @throws WayfException If the request does not contain a target parameter
	 */
	private String getTarget(HttpServletRequest req) throws WayfException {

		String target = (String) req.getAttribute("target");
		if (req.getParameter("target") != null) {
			target = req.getParameter("target");
		}
		if (target == null) {
			throw new WayfException("Invalid data from SHIRE: No target URL received.");
		}
		return target;
	}

}