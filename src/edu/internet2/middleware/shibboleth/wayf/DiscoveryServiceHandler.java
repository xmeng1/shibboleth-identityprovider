package edu.internet2.middleware.shibboleth.wayf;

import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;
import java.util.TreeSet;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;


public class DiscoveryServiceHandler {

	private final static Logger log = Logger.getLogger(DiscoveryServiceHandler.class.getName());

	private final static String DEFAULT_JSP_FILE = "/wayf.jsp";
	private final static String DEFAULT_ERROR_JSP_FILE = "/wayferror.jsp";
	
	private final String location;
	private final boolean isDefault;
	private final HandlerConfig config;
	//
	// hacked enum
	//
	
	private final List /*<IdPSiteSet>*/ siteSets = new ArrayList /*<IdPSiteSet>*/ ();
	
	
	protected DiscoveryServiceHandler(Element config, 
								      Hashtable /*<String, IdPSiteSet>*/ federations,
								      HandlerConfig defaultConfig) throws ShibbolethConfigurationException
	{
		this.config = new HandlerConfig(config, defaultConfig);
		
		location = config.getAttribute("location");
		
		if (location == null || location.equals("")) {
			
			log.error("DiscoveryService must have a location specified");
			throw new ShibbolethConfigurationException("DiscoveryService must have a location specified");
			
		}

		String attribute = ((Element) config).getAttribute("default");
		if (attribute != null && !attribute.equals("")) {
			isDefault = Boolean.valueOf(attribute).booleanValue();
		} else {
			isDefault = true;
		}
		
		NodeList list = config.getElementsByTagName("Federation");
		    
	    for (int i = 0; i < list.getLength(); i++ ) {
		    	
	    	attribute = ((Element) list.item(i)).getAttribute("identifier");
		    	
		    IdPSiteSet siteset = (IdPSiteSet) federations.get(attribute);
		    
		    if (siteset == null) {
		    	log.error("Handler " + location + ": could not find metadata for identifier " + attribute);
		    	throw new ShibbolethConfigurationException("Handler " + location + ": could not find metadata for identifier " + attribute);
		    }
		    
		    siteSets.add(siteset);
	    }

	    if (siteSets.size() == 0) {
			//
			// No Federations explicitly named
			//
			siteSets.addAll(federations.values());
		}
	}
	
	
	//
	// Standard Beany Methods
	//
	/**
	 * Returns the 'Name' of the service - the path used to identify the ServiceHandler 
	 */
	
	public String getLocation() {
		return location;
	}

	public boolean isDefault() {
		return isDefault;
	}

	public void doGet(HttpServletRequest req, HttpServletResponse res) {
		// Decide how to route the request based on query string
		String requestType = req.getParameter("action");
		if (requestType == null) {
			requestType = "lookup";
		}
		try {

			SamlIdPCookie cookie;
			
			if (config.getHandleCookie() == HandlerConfig.CLEAR_COOKIE) {
				
				//
				// Mark the cookie for deletion (unless we reset it later)
				
				SamlIdPCookie.deleteCookie(req, res);
				
				//
				// And create an empty cookie
				//
				cookie = new SamlIdPCookie(req, res, config.getCacheDomain());
				
			} else {

				cookie = SamlIdPCookie.getIdPCookie(req, res, config.getCacheDomain());
			}

			
			String searchSP = null;
			
			if (config.getLookupSp()) {
				searchSP = getProviderId(req);
			}
			
			List /*<IdPSite>*/ cookieList = cookie.getIdPList(siteSets, searchSP);
			
			//
			// Put if we have been told to
			//
			if (((config.getHandleCookie() == HandlerConfig.ALWAYS_FOLLOW_COOKIE) && (cookieList.size() > 0)) ||
				((config.getHandleCookie() == HandlerConfig.FOLLOW_SINGLE_COOKIE) && (cookieList.size() == 1))) {
				
				IdPSite site = (IdPSite) cookieList.get(0);
				
				//
				// Move name to front of cookie, and write back specifying a time of
				// zero (which will leave the time untouched)
				//
				cookie.addIdPName(site.getName(), config.getCacheExpiration());
				
				forwardToIdP(req, res, site);
			} else if (requestType.equals("search")) {
				
				handleSearch(req, res, cookieList);
				
			} else if (requestType.equals("selection")) {
				
				String origin = req.getParameter("origin");
				log.debug("Processing handle selection: " + origin);
				
				IdPSite site = IdPSiteSet.IdPforSP(siteSets, origin, searchSP);
				
				if (site == null) {
					handleLookup(req, res, cookieList);
				} else {
					
					//
					// Write back cache - if we were asked to
					//
					
					if ((req.getParameter("cache") != null)) {
                        if (req.getParameter("cache").equalsIgnoreCase("session")) {
                            cookie.addIdPName(origin, -1);
                        } else if (req.getParameter("cache").equalsIgnoreCase("perm")) {
                            cookie.addIdPName(origin, config.getCacheExpiration());
                        }
                    }
					forwardToIdP(req, res, site);
				}
			} else {
				handleLookup(req, res, cookieList);
			}
		} catch (WayfException we) {
			handleError(req, res, we);
		}

	}
	
	/**
	 * Displays a WAYF selection page.
	 * 
	 */
	private void handleLookup(HttpServletRequest req, HttpServletResponse res, List/*<IdPSite>*/ cookieList) throws WayfException {

		try {
			if ((getSHIRE(req) == null) || (getTarget(req) == null)) { throw new WayfException(
					"Invalid or missing data from SHIRE"); 
			}

			if (cookieList.size() > 0) {
				req.setAttribute("cookieList", cookieList);
			}
			req.setAttribute("shire", getSHIRE(req));
			req.setAttribute("target", getTarget(req));
			String providerId = getProviderId(req);
			if (providerId != null) {
				req.setAttribute("providerId", providerId);
			}

			Collection /*<IdPSiteSetEntry>*/ siteLists = null;
			if (config.getProvideListOfLists()) {
				siteLists = new ArrayList /*<IdPSiteSetEntry>*/(siteSets.size());
			}
			
			Collection /*<IdPSite>*/ sites = null;
			if (config.getProvideList()) {
				sites = new TreeSet/*<IdPSite>*/();
			}
	
			String searchSP = null;	
			
			if (config.getLookupSp()) {
				searchSP = providerId;
			}
			
			IdPSiteSet.getSiteLists(siteSets, searchSP, siteLists, sites);
			
			req.setAttribute("sites", sites);
			req.setAttribute("siteLists", siteLists);
			
			if (siteLists != null && siteLists.size() == 1) {
				req.setAttribute("singleSiteList", new Object());
			}

			req.setAttribute("time", new Long(new Date().getTime() / 1000).toString()); // Unix Time
			req.setAttribute("requestURL", req.getRequestURI().toString());

			log.debug("Displaying WAYF selection page.");
			RequestDispatcher rd = req.getRequestDispatcher(config.getJspFile());

			rd.forward(req, res);
		} catch (IOException ioe) {
			throw new WayfException("Problem displaying WAYF UI.\n" + ioe.getMessage());
		} catch (ServletException se) {
			throw new WayfException("Problem displaying WAYF UI.\n" +  se.getMessage());
		}
	}

	/**
	 * Looks for origin sites that match search terms supplied by the user
	 * 
	 */
	private void handleSearch(HttpServletRequest req, HttpServletResponse res, List /*<IdPSite>*/ cookieList) throws WayfException {

		String parameter = req.getParameter("string"); 
		if (parameter != null) {
			Collection/*<IdPSite>*/ sites = IdPSiteSet.seachForMatchingOrigins(siteSets, getProviderId(req), parameter, config);
			if (sites.size() != 0) {
				req.setAttribute("searchresults", sites);
			} else {
				req.setAttribute("searchResultsEmpty", "true");
			}
		}
		handleLookup(req, res, cookieList);
	}

	/**
	 * Uses an HTTP Status 307 redirect to forward the user the HS.
	 * 
	 * @param site - The Idp.
	 */
	private void forwardToIdP(HttpServletRequest req, HttpServletResponse res, IdPSite site)
			throws WayfException {

		String handleService = site.getAddressFor(); 
				
		if (handleService != null ) {

			log.info("Redirecting to selected Handle Service: " + handleService);
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
				//
				// That failed.  Purge the cache or we will go around again...
				//
				SamlIdPCookie.deleteCookie(req, res);
				throw new WayfException("Error forwarding to HS: \n" + ioe.getMessage());
			}
		} else {
			log.error("Error finding to IdP: " + site.getDisplayName());
			handleLookup(req, res, null);
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
		RequestDispatcher rd = req.getRequestDispatcher(config.getErrorJspFile());

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

		String param = req.getParameter("providerId");
		if (param != null && !(param.length() == 0)) {
			return req.getParameter("providerId");

		} else {
			String attr = (String) req.getAttribute("providerId");
			if (attr == null || attr.length() == 0) { return null; }
			return attr;
		}
	}
}

