package edu.internet2.middleware.shibboleth.wayf;

import java.util.HashSet;

import org.apache.log4j.Logger;

/**
 * Class used by the  WAYF service to determine runtime options
 * Most of the fields of this class should have reasonable defaults set
 * @author        Walter Hoehn
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

	/**
	 * Constructor for WayfConfig.
	 */
	public WayfConfig() {
		super();
	}

	/**
	 * Gets the wd.
	 * @return Returns a WayfOrigins
	 */
	public static WayfOrigins getWAYFData() {
		return wd;
	}

	/**
	 * Sets the wd.
	 * @param wd The wd to set
	 */
	public void setWAYFData(WayfOrigins wd) {
		WayfConfig.wd = wd;
	}

	/**
	 * Gets the searchResultEmptyText.
	 * @return Returns a String
	 */
	public static String getSearchResultEmptyText() {
		return searchResultEmptyText;
	}

	/**
	 * Sets the searchResultEmptyText.
	 * @param searchResultEmptyText The searchResultEmptyText to set
	 */
	public void setSearchResultEmptyText(String searchResultEmptyText) {
		WayfConfig.searchResultEmptyText = searchResultEmptyText;
	}

	/**
	 * Gets the helpText.
	 * @return Returns a String
	 */
	public static String getHelpText() {
		return helpText;
	}

	/**
	 * Sets the helpText.
	 * @param helpText The helpText to set
	 */
	public void setHelpText(String helpText) {
		WayfConfig.helpText = helpText;
	}

	/**
	 * Gets the supportContact.
	 * @return Returns a String
	 */
	public static String getSupportContact() {
		return supportContact;
	}

	/**
	 * Sets the supportContact.
	 * @param supportContact The supportContact to set
	 */
	public void setSupportContact(String supportContact) {
		WayfConfig.supportContact = supportContact;
	}

	/**
	 * Gets the logoLocation.
	 * @return Returns a String
	 */
	public static String getLogoLocation() {
		return logoLocation;
	}

	/**
	 * Sets the logoLocation.
	 * @param logoLocation The logoLocation to set
	 */
	public void setLogoLocation(String logoLocation) {
		WayfConfig.logoLocation = logoLocation;
	}

	/**
	 * Gets the location.
	 * @return Returns a String
	 */
	public static String getLocation() {
		return location;
	}

	/**
	 * Sets the location.
	 * @param location The location to set
	 */
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

	/**
	* Gets the cache.
	* @return Returns a String
	*/
	public static String getCache() {
		return cache;
	}

	/**
	 * Sets the cache.
	 * @param cache The cache to set
	 */
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