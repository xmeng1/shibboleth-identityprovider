package edu.internet2.middleware.shibboleth.wayf;

import java.io.IOException;
import java.io.InputStream;
import java.net.URLEncoder;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.xml.sax.SAXException;

/**
 * A servlet implementation of the Shibboleth WAYF service.  Allows a browser user to 
 * select from among a group of origin sites.  User selection is optionally cached 
 * and the user is forwarded to the HandleService appropriate to his selection.
 *
 * @author Walter Hoehn wassa&#064;columbia.edu
 */

public class WayfService extends HttpServlet {

	private String wayfConfigFileLocation;
	private static Logger log = Logger.getLogger(WayfService.class.getName());
	private String log4jConfigFileLocation;

	/**
	 * @see GenericServlet#init()
	 */
	public void init() throws ServletException {

		super.init();
		loadInitParams();
		initLogger();
		//initialize configuration from file
		InputStream is =
			getServletContext().getResourceAsStream(wayfConfigFileLocation);
		WayfConfigDigester digester = new WayfConfigDigester();
		try {
			digester.parse(is);
		} catch (SAXException se) {
			log.fatal("Error parsing WAYF configuration file.", se);
			throw new ServletException(
				"Error parsing WAYF configuration file.",
				se);
		} catch (IOException ioe) {
			log.fatal("Error reading WAYF configuration file.", ioe);
			throw new ServletException(
				"Error reading WAYF configuration file.",
				ioe);
		}

		//Setup appliation-wide beans from config
		getServletContext().setAttribute(
			"originsets",
			WayfConfig.getWAYFData().getOriginSets());
		String wayfLocation = WayfConfig.getLocation();
		if (wayfLocation == null) {
			wayfLocation = "WAYF";
		}
		getServletContext().setAttribute("wayfLocation", wayfLocation);
		getServletContext().setAttribute(
			"supportContact",
			WayfConfig.getSupportContact());
		getServletContext().setAttribute("helpText", WayfConfig.getHelpText());
		getServletContext().setAttribute(
			"searchResultEmptyText",
			WayfConfig.getSearchResultEmptyText());
		getServletContext().setAttribute(
			"logoLocation",
			WayfConfig.getLogoLocation());
	}

	private void loadInitParams() {

		wayfConfigFileLocation =
			getServletConfig().getInitParameter("WAYFConfigFileLocation");
		if (wayfConfigFileLocation == null) {
			wayfConfigFileLocation = "/WEB-INF/conf/shibboleth.xml";
		}
		log4jConfigFileLocation =
			getServletConfig().getInitParameter("log4jConfigFileLocation");
		if (log4jConfigFileLocation == null) {
			log4jConfigFileLocation = "/WEB-INF/conf/log4j.properties";
		}

	}

	/**
	 * Starts up Log4J.
	 */

	private void initLogger() {

		PropertyConfigurator.configure(
			getServletContext().getRealPath("/") + log4jConfigFileLocation);

	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest, HttpServletResponse)
	 */
	public void doGet(HttpServletRequest req, HttpServletResponse res) {

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
				WayfCacheFactory.getInstance().deleteHsFromCache(req, res);
				handleLookup(req, res);
			} else if (WayfCacheFactory.getInstance().hasCachedHS(req)) {
				handleRedirect(
					req,
					res,
					WayfCacheFactory.getInstance().getCachedHS(req));
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

	private void handleLookup(HttpServletRequest req, HttpServletResponse res)
		throws WayfException {

		if ((getSHIRE(req) == null) || (getTarget(req) == null)) {
			throw new WayfException("Invalid or missing data from SHIRE");
		}
		req.setAttribute("shire", getSHIRE(req));
		req.setAttribute("target", getTarget(req));
		req.setAttribute("encodedShire", URLEncoder.encode(getSHIRE(req)));
		req.setAttribute("encodedTarget", URLEncoder.encode(getTarget(req)));

		RequestDispatcher rd = req.getRequestDispatcher("/wayf.jsp");
		try {
			rd.forward(req, res);
		} catch (IOException ioe) {
			throw new WayfException(
				"Problem displaying WAYF UI." + ioe.toString());
		} catch (ServletException se) {
			throw new WayfException(
				"Problem displaying WAYF UI." + se.toString());
		}
	}

	private void handleSearch(HttpServletRequest req, HttpServletResponse res)
		throws WayfException {

		if (req.getParameter("string") != null) {
			Origin[] origins =
				WayfConfig.getWAYFData().seachForMatchingOrigins(
					req.getParameter("string"));
			if (origins.length != 0) {
				req.setAttribute("searchresults", origins);
			} else {
				req.setAttribute("searchResultsEmpty", "true");
			}
		}
		handleLookup(req, res);

	}

	private void handleSelection(
		HttpServletRequest req,
		HttpServletResponse res)
		throws WayfException {

		String handleService =
			WayfConfig.getWAYFData().lookupHSbyName(req.getParameter("origin"));
		if (handleService == null) {
			handleLookup(req, res);
		} else {
			WayfCacheFactory.getInstance().addHsToCache(
				handleService,
				req,
				res);
			handleRedirect(req, res, handleService);
		}

	}

	private void handleRedirect(
		HttpServletRequest req,
		HttpServletResponse res,
		String handleService)
		throws WayfException {

		String shire = getSHIRE(req);
		String target = getTarget(req);

		try {
			res.sendRedirect(
				handleService
					+ "?target="
					+ URLEncoder.encode(target)
					+ "&shire="
					+ URLEncoder.encode(shire));
		} catch (IOException ioe) {
			throw new WayfException(
				"Error forwarding to HS: " + ioe.toString());
		}

	}

	private void handleError(
		HttpServletRequest req,
		HttpServletResponse res,
		WayfException we) {

		log.error("WAYF Failure: " + we.toString());
		req.setAttribute("errorText", we.toString());
		RequestDispatcher rd = req.getRequestDispatcher("/wayferror.jsp");

		try {
			rd.forward(req, res);
		} catch (IOException ioe) {
			log.error(
				"Problem trying to display WAYF error page: " + ioe.toString());
		} catch (ServletException se) {
			log.error(
				"Problem trying to display WAYF error page: " + se.toString());
		}
	}

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