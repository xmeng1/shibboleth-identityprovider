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