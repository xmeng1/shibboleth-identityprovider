package edu.internet2.middleware.shibboleth.wayf;

import java.util.HashSet;

import org.apache.log4j.Logger;

/**
 * Class used by the  WAYF service to determine runtime options
 * Most of the fields of this class should have reasonable defaults.
 * @author Walter Hoehn wassa&#064;columbia.edu
 */

public class WayfConfig {

	private static Logger log = Logger.getLogger(WayfConfig.class.getName());

	private String logoLocation = "images/internet2.gif";
	private String supportContact = "mailto:shib-support@internet2.org";
	private String helpText =
		"In order to fulfill the request for the  web resource you "
			+ "have just chosen, information must first be obtained from "
			+ "your home institution. Please select the institution with "
			+ "which you are affiliated.";
	private String searchResultEmptyText =
		"No institution found that matches your search " + "criteria, please try again.";
	private HashSet ignoredForMatch = new HashSet();
	private int cacheExpiration;
	private String cacheDomain;
	private String cacheType = "COOKIES";

	public WayfConfig() {
		super();
	}

	public String getSearchResultEmptyText() {
		return searchResultEmptyText;
	}

	public void setSearchResultEmptyText(String searchResultEmptyText) {
		this.searchResultEmptyText = searchResultEmptyText;
	}

	public String getHelpText() {
		return helpText;
	}

	public void setHelpText(String helpText) {
		this.helpText = helpText;
	}

	public String getSupportContact() {
		return supportContact;
	}

	public void setSupportContact(String supportContact) {
		this.supportContact = supportContact;
	}

	public String getLogoLocation() {
		return logoLocation;
	}

	public void setLogoLocation(String logoLocation) {
		this.logoLocation = logoLocation;
	}

	/**
	 * Determines if a particular string token should be used for matching when a user searches for origins.
	 * @param str The string to lookup
	 */
	public boolean isIgnoredForMatch(String str) {

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

	public String getCacheType() {
		return cacheType;
	}

	public void setCacheType(String cache) {
		if (cache.toUpperCase().equals("NONE")
			|| cache.toUpperCase().equals("SESSION")
			|| cache.toUpperCase().equals("COOKIES")) {
			this.cacheType = cache.toUpperCase();
		} else {
			log.warn("Cache type :" + cache + ": not recognized, using default.");
		}
	}

	/**
	 * Returns the cacheDomain.
	 * @return String
	 */
	public String getCacheDomain() {
		return cacheDomain;
	}


	/**
	 * Returns the cacheExpiration.
	 * @return int
	 */
	public int getCacheExpiration() {
		return cacheExpiration;
	}


	/**
	 * Sets the cacheDomain.
	 * @param cacheDomain The cacheDomain to set
	 */
	public void setCacheDomain(String cacheDomain) {
		this.cacheDomain = cacheDomain;
	}


	/**
	 * Sets the cacheExpiration.
	 * @param cacheExpiration The cacheExpiration to set
	 */
	public void setCacheExpiration(int cacheExpiration) {
		this.cacheExpiration = cacheExpiration;
	}


}