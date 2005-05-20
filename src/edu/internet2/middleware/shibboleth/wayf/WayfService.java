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

package edu.internet2.middleware.shibboleth.wayf;

import java.io.IOException;
import java.io.InputStream;
import java.net.URLEncoder;
import java.util.Date;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.UnavailableException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.xml.sax.SAXException;

import edu.internet2.middleware.shibboleth.common.ResourceWatchdog;
import edu.internet2.middleware.shibboleth.common.ShibResource;
import edu.internet2.middleware.shibboleth.common.ResourceWatchdogExecutionException;
import edu.internet2.middleware.shibboleth.common.ShibResource.ResourceNotAvailableException;

/**
 * A servlet implementation of the Shibboleth WAYF service. Allows a browser user to select from among a group of origin
 * sites. User selection is optionally cached and the user is forwarded to the HandleService appropriate to his
 * selection.
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
	ResourceWatchdog watchdog;

	/**
	 * @see GenericServlet#init()
	 */
	public void init() throws ServletException {

		super.init();
		log.info("Initializing WAYF.");
		loadInitParams();
		log.info("Loading configuration from file.");
		configure();

		log.info("Initailizing site metadata watchdog.");
		try {
			watchdog = new SitesFileWatchdog(siteConfigFileLocation, this);
			watchdog.start();
		} catch (ResourceNotAvailableException e) {
			log.error("Sites file watchdog could not be initialized: " + e);
		}

		// Setup Cacheing options
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

		loadSiteConfig();
	}

	private void loadSiteConfig() throws UnavailableException {

		try {

			InputStream siteIs = new ShibResource(siteConfigFileLocation, this.getClass()).getInputStream();
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

		getServletContext().setAttribute("originsets", getOrigins().getOriginSets());
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
		// Tell the browser not to cache the WAYF page
		res.setHeader("Cache-Control", "no-cache");
		res.setHeader("Pragma", "no-cache");
		res.setDateHeader("Expires", 0);

		// Decide how to route the request based on query string
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
				forwardToHS(req, res, WayfCacheFactory.getInstance(config.getCacheType()).getCachedHS(req));
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

	public void destroy() {

		if (watchdog != null && watchdog.isAlive()) {
			watchdog.interrupt();
		}
	}

	/**
	 * Displays a WAYF selection page.
	 */
	private void handleLookup(HttpServletRequest req, HttpServletResponse res) throws WayfException {

		try {
			if ((getSHIRE(req) == null) || (getTarget(req) == null)) { throw new WayfException(
					"Invalid or missing data from SHIRE"); }
			req.setAttribute("shire", getSHIRE(req));
			req.setAttribute("target", getTarget(req));
			String providerId = getProviderId(req);
			if (providerId != null) {
				req.setAttribute("providerId", providerId);
			}
			req.setAttribute("time", new Long(new Date().getTime() / 1000).toString()); // Unix Time
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
			Origin[] origins = getOrigins().seachForMatchingOrigins(req.getParameter("string"), config);
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
		String handleService = getOrigins().lookupHSbyName(req.getParameter("origin"));
		if (handleService == null) {
			handleLookup(req, res);
		} else {
			if ((req.getParameter("cache") != null) && req.getParameter("cache").equalsIgnoreCase("TRUE")) {
				WayfCacheFactory.getInstance(config.getCacheType(), wOptions).addHsToCache(handleService, req, res);
			}
			forwardToHS(req, res, handleService);
		}

	}

	/**
	 * Uses an HTTP Status 307 redirect to forward the user the HS.
	 * 
	 * @param handleService
	 *            The URL of the Shiboleth HS.
	 */
	private void forwardToHS(HttpServletRequest req, HttpServletResponse res, String handleService)
			throws WayfException {

		log.info("Redirecting to selected Handle Service");
		try {
			StringBuffer buffer = new StringBuffer(handleService + "?target="
					+ URLEncoder.encode(getTarget(req), "UTF-8") + "&shire="
					+ URLEncoder.encode(getSHIRE(req), "UTF-8"));
			String providerId = getProviderId(req);
			log.debug("WALTER: (" + providerId + ").");
			if (providerId != null) {
				buffer.append("&providerId=" + URLEncoder.encode(getProviderId(req), "UTF-8"));
			}
			buffer.append("&time=" + new Long(new Date().getTime() / 1000).toString()); // Unix Time
			res.sendRedirect(buffer.toString());
		} catch (IOException ioe) {
			throw new WayfException("Error forwarding to HS: " + ioe.toString());
		}

	}

	/**
	 * Handles all "recoverable" errors in WAYF processing by logging the error and forwarding the user to an
	 * appropriate error page.
	 * 
	 * @param we
	 *            The WayfException respective to the error being handled
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
	 * 
	 * @throws WayfException
	 *             If the request does not contain a shire parameter.
	 */
	private String getSHIRE(HttpServletRequest req) throws WayfException {

		String shire = (String) req.getAttribute("shire");
		if (req.getParameter("shire") != null) {
			shire = req.getParameter("shire");
		}
		if (shire == null) { throw new WayfException("Invalid data from SHIRE: No acceptance URL received."); }
		return shire;
	}

	/**
	 * Retrieves the user's target URL from the request.
	 * 
	 * @throws WayfException
	 *             If the request does not contain a target parameter
	 */
	private String getTarget(HttpServletRequest req) throws WayfException {

		String target = (String) req.getAttribute("target");
		if (req.getParameter("target") != null) {
			target = req.getParameter("target");
		}
		if (target == null) { throw new WayfException("Invalid data from SHIRE: No target URL received."); }
		return target;
	}

	private String getProviderId(HttpServletRequest req) {

		if (req.getParameter("providerId") != null && !(req.getParameter("providerId").length() == 0)) {
			return req.getParameter("providerId");

		} else {
			String attr = (String) req.getAttribute("providerId");
			if (attr == null || attr.length() == 0) { return null; }
			return attr;
		}
	}

	private WayfOrigins getOrigins() {

		synchronized (originConfig) {
			return originConfig;
		}
	}

	private void reloadOriginMetadata() throws UnavailableException {

		WayfOrigins safetyCache = getOrigins();
		try {
			synchronized (originConfig) {
				loadSiteConfig();
				getServletContext().setAttribute("originsets", getOrigins().getOriginSets());
			}

		} catch (UnavailableException e) {
			log.error("Failed to load updated origin site metadata: " + e);
			synchronized (originConfig) {
				originConfig = safetyCache;
			}
			throw e;
		}
	}

	private class SitesFileWatchdog extends ResourceWatchdog {

		private WayfService wayfService;

		private SitesFileWatchdog(String sitesFileLocation, WayfService wayfService)
				throws ResourceNotAvailableException {

			super(new ShibResource(sitesFileLocation, wayfService.getClass()));
			this.wayfService = wayfService;
		}

		/**
		 * @see edu.internet2.middleware.shibboleth.common.ResourceWatchdog#doOnChange()
		 */
		protected void doOnChange() throws ResourceWatchdogExecutionException {

			try {
				wayfService.reloadOriginMetadata();
			} catch (UnavailableException e) {
				try {
					log.error("Sites file at (" + resource.getURL().toString() + ") could not be loaded: " + e);
				} catch (IOException ioe) {
					log.error("Sites file could not be loaded.");
				} finally {
					throw new ResourceWatchdogExecutionException("Watchdog reload failed.");
				}
			}
		}
	}
}
