package edu.internet2.middleware.shibboleth.wayf;

import java.io.IOException;
import java.io.InputStream;
import java.net.URLEncoder;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.log4j.Logger;
import org.xml.sax.SAXException;

/**
 * This is the main handler servlet for the WAYF service.  It configures itself, chooses among 
 * several handler methods for each request, populates some beans (model), and then passes to an
 * appropriate jsp page.
 *
 * @author		Walter Hoehn
 */

public class WayfService extends HttpServlet {

	private String wayfConfigFileLocation;
	private static Logger log = Logger.getLogger(WayfService.class.getName());

	public void init() throws ServletException {

		super.init();

		loadInitParams();
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

	public void doGet(HttpServletRequest req, HttpServletResponse res) {

		//Tell the browser not to cache the WAYF page
		res.setHeader("Cache-Control", "no-cache");
		res.setHeader("Pragma", "no-cache");

		//Decide how to route the request based on query string
		String requestType = req.getParameter("action");
		if (requestType == null) {
			requestType = "lookup";
		}
		try {
			if (requestType.equals("deleteFromCache")) {
				handleDeleteFromCache(req, res);
			} else if (hasCachedHS(req)) {
				handleRedirect(req, res, getCachedHS(req));
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

	private void loadInitParams() {

		wayfConfigFileLocation =
			getServletConfig().getInitParameter("WAYFConfigFileLocation");
		if (wayfConfigFileLocation == null) {
			wayfConfigFileLocation = "/WEB-INF/conf/shibboleth.xml";
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

	private void handleDeleteFromCache(
		HttpServletRequest req,
		HttpServletResponse res)
		throws WayfException {

		if (WayfConfig.getCache().equals("SESSION")) {

			HttpSession session = req.getSession(false);
			if (session != null) {
				session.removeAttribute("selectedHandleService");
			}

		} else if (WayfConfig.getCache().equals("COOKIES")) {

			Cookie[] cookies = req.getCookies();
			for (int i = 0; i < cookies.length; i++) {
				if (cookies[i].getName().equals("selectedHandleService")) {
					cookies[i].setMaxAge(0);
					res.addCookie(cookies[i]);
				}
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
			addHsToCache(req, res, handleService);
			handleRedirect(req, res, handleService);
		}

	}

	private void addHsToCache(
		HttpServletRequest req,
		HttpServletResponse res,
		String handleService) {

		if (WayfConfig.getCache().equals("NONE")) {
			return;
		} else if (WayfConfig.getCache().equals("SESSION")) {

			HttpSession session = req.getSession(true);
			session.setMaxInactiveInterval(7200);
			session.setAttribute("selectedHandleService", handleService);
		} else if (WayfConfig.getCache().equals("COOKIES")) {

			Cookie cacheCookie =
				new Cookie("selectedHandleService", handleService);
			cacheCookie.setComment(
				"Used to cache selection of a user's Handle Service");

			//Should probably get this stuff from config
			/**     
			 cacheCookie.setMaxAge();
			 cacheCookie.setDomain();
			 **/
			res.addCookie(cacheCookie);

		} else {
			log.warn(
				"Invalid Cache type specified: running with cache type NONE.");
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

	private boolean hasCachedHS(HttpServletRequest req) {

		if (getCachedHS(req) == null) {
			return false;
		} else {
			return true;
		}
	}
	private String getCachedHS(HttpServletRequest req) {

		if (WayfConfig.getCache().equals("NONE")) {
			return null;
		} else if (WayfConfig.getCache().equals("SESSION")) {
			HttpSession session = req.getSession(false);
			if (session == null) {
				return null;
			}
			return (String) session.getAttribute("selectedHandleService");

		} else if (WayfConfig.getCache().equals("COOKIES")) {

			Cookie[] cookies = req.getCookies();
			for (int i = 0; i < cookies.length; i++) {
				if (cookies[i].getName().equals("selectedHandleService")) {
					return cookies[i].getValue();
				}
			}

		}
		log.warn("Invalid Cache type specified: running with cache type NONE.");
		return null;

	}

}