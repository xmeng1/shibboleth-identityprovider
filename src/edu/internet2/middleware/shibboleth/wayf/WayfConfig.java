package edu.internet2.middleware.shibboleth.wayf;

import java.util.HashSet;

import org.apache.log4j.Logger;

/**
 * Class used by the  WAYF service to determine runtime options
 * Most of the fields of this class should have reasonable defaults set
 * @author Walter Hoehn wassa&#064;columbia.edu
 */

public class WayfConfig {

	private static Logger log = Logger.getLogger(WayfConfig.class.getName());

	private static WayfOrigins wd;
	private static String location;
	private static String logoLocation = "images/internet2.gif";
	private static String supportContact = "mailto:shib-support@internet2.org";
	private static String helpText =
		"In order to fulfill the request for the  web resource you "
			+ "have just chosen, information must first be obtained from "
			+ "your home institution. Please select the institution with "
			+ "which you are affiliated.";
	private static String searchResultEmptyText =
		"No institution found that matches your search "
			+ "criteria, please try again.";
	private static HashSet ignoredForMatch = new HashSet();

	private static String cache = "SESSION";

	public WayfConfig() {
		super();
	}

	public static WayfOrigins getWAYFData() {
		return wd;
	}

	public void setWAYFData(WayfOrigins wd) {
		WayfConfig.wd = wd;
	}

	public static String getSearchResultEmptyText() {
		return searchResultEmptyText;
	}

	public void setSearchResultEmptyText(String searchResultEmptyText) {
		WayfConfig.searchResultEmptyText = searchResultEmptyText;
	}

	public static String getHelpText() {
		return helpText;
	}

	public void setHelpText(String helpText) {
		WayfConfig.helpText = helpText;
	}

	public static String getSupportContact() {
		return supportContact;
	}

	public void setSupportContact(String supportContact) {
		WayfConfig.supportContact = supportContact;
	}

	public static String getLogoLocation() {
		return logoLocation;
	}

	public void setLogoLocation(String logoLocation) {
		WayfConfig.logoLocation = logoLocation;
	}

	public static String getLocation() {
		return location;
	}

	public void setLocation(String location) {
		WayfConfig.location = location;
	}

	/**
	 * Determines if a particular string token should be used for matching when a user searches for origins.
	 * @param str The string to lookup
	 */
	public static boolean isIgnoredForMatch(String str) {

		if (ignoredForMatch.contains(str.toLowerCase())) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Sets the tokens that should be ignored when a user searches for an origin site.
	 * @param s The ignored tokens are passed as a single string, each separated by whitespace
	 */
	public void addIgnoredForMatch(String s) {

		ignoredForMatch.add(s.toLowerCase());
	}

	public static String getCache() {
		return cache;
	}

	public void setCache(String cache) {
		if (cache.toUpperCase().equals("NONE")
			|| cache.toUpperCase().equals("SESSION")
			|| cache.toUpperCase().equals("COOKIES")) {
			WayfConfig.cache = cache.toUpperCase();
		} else {
			log.warn(
				"Cache type :" + cache + ": not recognized, using default.");
		}
	}

}