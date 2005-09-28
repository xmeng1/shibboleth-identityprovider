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
import java.net.URLEncoder;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import javax.servlet.GenericServlet;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.UnavailableException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;

import edu.internet2.middleware.shibboleth.common.ShibResource.ResourceNotAvailableException;
import edu.internet2.middleware.shibboleth.metadata.Metadata;
import edu.internet2.middleware.shibboleth.metadata.MetadataException;
import edu.internet2.middleware.shibboleth.metadata.provider.XMLMetadata;
import edu.internet2.middleware.shibboleth.xml.Parser;

/**
 * A servlet implementation of the Shibboleth WAYF service. Allows a browser
 * user to select from among a group of origin sites. User selection is
 * optionally cached and the user is forwarded to the HandleService appropriate
 * to his selection.
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */
public class WayfService extends HttpServlet {

    private String wayfConfigFileLocation;

    private String siteConfigFileLocation;

    private WayfConfig config;

    private Metadata metadata;

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

        log.info("Initializing site metadata & watchdog");
        try {
            metadata = new XMLMetadata(siteConfigFileLocation);
        } catch (ResourceNotAvailableException e) {
            log.error("Sites file watchdog could not be initialized: " + e);
            throw new ServletException(e);
        } catch (MetadataException e) {
            log.error("Sites files could not be parsed" + e);
            throw new ServletException(e);
        }

        initViewConfig();
        log.info("WAYF initialization completed.");
    }

    /**
     * Populates WayfConfig from file contents.
     */
    private void configure() throws UnavailableException {
        try {
            Document doc = Parser.loadDom(wayfConfigFileLocation, true);
            config = new WayfConfig(doc.getDocumentElement());
        } catch (IOException e) {
            log.fatal("Error Loading WAYF configuration file.", e);
            throw new UnavailableException("Error parsing WAYF configuration file.");
        } catch (Exception e) {
            // All other exceptions are from the parsing
            log.fatal("Error parsing WAYF configuration file.", e);
            throw new UnavailableException("Error parsing WAYF configuration file.");
        }
    }

    /**
     * Setup application-wide beans for view
     */
    private void initViewConfig() {

        getServletContext().setAttribute("supportContact", config.getSupportContact());
        getServletContext().setAttribute("helpText", config.getHelpText());
        getServletContext().setAttribute("searchResultEmptyText", config.getSearchResultEmptyText());
        getServletContext().setAttribute("logoLocation", config.getLogoLocation());
    }

    /**
     * Reads parameters from web.xml <init-param /> construct.
     */
    private void loadInitParams() {

        wayfConfigFileLocation = getServletContext().getInitParameter("WAYFConfigFileLocation");
        if (wayfConfigFileLocation == null) {
            log.info("No WAYFConfigFileLocation paramter found in servlet context, checking in servlet config");
            wayfConfigFileLocation = getServletConfig().getInitParameter("WAYFConfigFileLocation");
            if (wayfConfigFileLocation == null) {
                log.warn("No WAYFConfigFileLocation parameter found... using default location.");
                wayfConfigFileLocation = "/conf/wayfconfig.xml";
            }
        }

        siteConfigFileLocation = getServletContext().getInitParameter("SiteConfigFileLocation");
        if (siteConfigFileLocation == null) {
            log.info("No SiteConfigFileLocation paramter found in servlet context, checking in servlet config");
            siteConfigFileLocation = getServletConfig().getInitParameter("SiteConfigFileLocation");
            if (siteConfigFileLocation == null) {
                log.warn("No SiteonfigFileLocation parameter found... using default location.");
                siteConfigFileLocation = "/conf/metadata.xml";
            }
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
                SamlIdPCookie.deleteCookie(req, res);
                handleLookup(req, res);
                return;
            }

            SamlIdPCookie cookie;
            if (req.getParameter("nolookup") == null) {
                cookie = SamlIdPCookie.getIdPCookie(req, res, config.getCacheDomain());
            } else {
                // For the test case, do not do a cache lookup, start as empty
                cookie = new SamlIdPCookie(req, res, config.getCacheDomain());
            }

            if (requestType.equals("search")) {
                handleSearch(req, res);
            } else if (requestType.equals("selection")) {
                String origin = req.getParameter("origin");
                log.debug("Processing handle selection: " + origin);
                if (origin == null) {
                    handleLookup(req, res);
                } else {
                    if ((req.getParameter("cache") != null)) {
                        if (req.getParameter("cache").equalsIgnoreCase("session")) {
                            cookie.addIdPName(origin, 0);
                        } else if (req.getParameter("cache").equalsIgnoreCase("perm")) {
                            cookie.addIdPName(origin, config.getCacheExpiration());
                        }
                    }
                    redirectToIdP(req, res, origin, cookie);
                }
            } else {
                // Try for a cache hit
                String idPName = null;
                Iterator it = cookie.iterator();

                //
                // The cached data may contain several IdPs, some of which we do
                // not know about
                // so iterate down until we find one we do know about
                //  
                while (it.hasNext()) {
                    idPName = (String) it.next();
                    if (metadata.lookup(idPName) != null) {
                        break;
                    }
                }

                if (idPName != null) {
                    //
                    // move the name to the head of the list, preserving the
                    // cache expiration
                    //
                    cookie.addIdPName(idPName, 0);
                    redirectToIdP(req, res, idPName, cookie);
                } else {
                    handleLookup(req, res);
                }
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

            req.setAttribute("sites", IdPSite.getIdPSites(metadata));
            req.setAttribute("shire", getSHIRE(req));
            req.setAttribute("target", getTarget(req));
            String providerId = getProviderId(req);
            if (providerId != null) {
                req.setAttribute("providerId", providerId);
            }

            req.setAttribute("time", new Long(new Date().getTime() / 1000).toString()); // Unix
            // Time
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

        String parameter = req.getParameter("string");
        if (parameter != null) {
            Collection sites = IdPSite.seachForMatchingOrigins(metadata, parameter, config);
            if (sites.size() != 0) {
                req.setAttribute("searchresults", sites);
            } else {
                req.setAttribute("searchResultsEmpty", "true");
            }
        }
        handleLookup(req, res);
    }

    /**
     * Registers a user's HS selection and forwards appropriately
     */
    private void redirectToIdP(HttpServletRequest req, HttpServletResponse res, String idPName, SamlIdPCookie cookie)
            throws WayfException {
        String idPSSOEndPoint = null;
        try {
            //
            // If we have had a refresh between then and now the following will
            // fail
            //
            idPSSOEndPoint = metadata.lookup(idPName).getIDPSSODescriptor(
                    edu.internet2.middleware.shibboleth.common.XML.SHIB_NS).getSingleSignOnServiceManager()
                    .getDefaultEndpoint().getLocation();
        } catch (Exception ex) {
            //
            // remove this entry (only) from the cache
            //
            cookie.deleteIdPName(idPName);
            log.error("Error dispatching to IdP: ", ex);
        }

        if (idPSSOEndPoint != null) {
            log.info("Redirecting to SSO at selected IdP: " + idPSSOEndPoint);
            try {
                StringBuffer buffer = new StringBuffer(idPSSOEndPoint).append("?target=");
                buffer.append(URLEncoder.encode(getTarget(req), "UTF-8")).append("&shire=");
                buffer.append(URLEncoder.encode(getSHIRE(req), "UTF-8"));
                String providerId = getProviderId(req);
                log.debug("WALTER: (" + providerId + ").");
                if (providerId != null) {
                    buffer.append("&providerId=").append(URLEncoder.encode(getProviderId(req), "UTF-8"));
                }
                buffer.append("&time=").append(new Long(new Date().getTime() / 1000).toString()); // Unix
                // Time
                res.sendRedirect(buffer.toString());
            } catch (IOException ioe) {
                //
                // remove this entry (only) from the cache
                //
                cookie.deleteIdPName(idPName);
                throw new WayfException("Error forwarding to IdP SSO endpoint: " + ioe.toString());
            }
        } else {
            //
            // We
            handleLookup(req, res);
        }
    }

    /**
     * Handles all "recoverable" errors in WAYF processing by logging the error
     * and forwarding the user to an appropriate error page.
     * 
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
     * 
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
     * 
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

    private String getProviderId(HttpServletRequest req) {

        if (req.getParameter("providerId") != null && !(req.getParameter("providerId").length() == 0)) {
            return req.getParameter("providerId");

        } else {
            String attr = (String) req.getAttribute("providerId");
            if (attr == null || attr.length() == 0) {
                return null;
            }
            return attr;
        }
    }
}
