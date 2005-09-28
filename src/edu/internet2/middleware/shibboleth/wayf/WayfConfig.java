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

import java.util.HashSet;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;

/**
 * Class used by the WAYF service to determine runtime options Most of the fields of this class should have reasonable
 * defaults.
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */

public class WayfConfig {

	private static Logger log = Logger.getLogger(WayfConfig.class.getName());

	private String logoLocation = "images/internet2.gif";
	private String supportContact = "mailto:shib-support@internet2.org";
	private String helpText = "In order to fulfill the request for the  web resource you "
			+ "have just chosen, information must first be obtained from "
			+ "your home institution. Please select the institution with " + "which you are affiliated.";
	private String searchResultEmptyText = "No institution found that matches your search "
			+ "criteria, please try again.";
	private HashSet ignoredForMatch = new HashSet();
	private int cacheExpiration;
	private String cacheDomain;

	private String getValue(Element element, String what) throws ShibbolethConfigurationException
	{
		NodeList list = element.getElementsByTagName(what);
	    
	    if (list.getLength() > 0) {
	    	if (list.getLength() > 1) {
	    		throw new ShibbolethConfigurationException("More than one <" + what + "/> element");
	    	}
	    		
	    	return list.item(0).getTextContent();
	    }
	    return null;
	}
	
	/**
	 * 
	 * Parse the Supplied XML element into a new WayfConfig Object
	 * 
	 */
	
	public WayfConfig(Element config) throws ShibbolethConfigurationException {

	    if (!config.getTagName().equals("WayfConfig")) { 

		throw new ShibbolethConfigurationException(
		    "Unexpected configuration data.  <WayfConfig/> is needed."); 
	    }

	    log.debug("Loading global configuration properties.");

	    String raw = config.getAttribute("cacheDomain");

	    if ((raw != null) && (raw != "")) {
	    	setCacheDomain(raw);
	    }
	    	
	    raw = config.getAttribute("cacheExpiration");
	    if ((raw != null) && (raw != "")) {
	    	
	    	try {

	    		setCacheExpiration(Integer.parseInt(raw));
	    	} catch (NumberFormatException ex) {
	    		
	    		throw new ShibbolethConfigurationException("Invalid CacheExpiration value - " + raw, ex);
	    	}
	    }

	    raw = config.getAttribute("logoLocation");
	    if ((raw != null) && (raw != "")) {
	    	
	    	setLogoLocation(raw);
	    }
	    
	    raw = config.getAttribute("supportContact");
	    if ((raw != null) && (raw != "")) {
	    	
	    	setSupportContact(raw);
	    }
	    
	    raw = getValue(config, "HelpText");
	    
	    if ((raw != null) && (raw != "")) {
	    	    	
	    	setHelpText(raw);
	    }

	    raw = getValue(config, "SearchResultEmptyText");
	    
	    if ((raw != null) && (raw != "")) {
	    	
	    	setSearchResultEmptyText(raw);
	    }
	    
	    NodeList list = config.getElementsByTagName("SearchIgnore");
	    
	    for (int i = 0; i < list.getLength(); i++ ) {
	    	
	    	NodeList inner = ((Element) list.item(i)).getElementsByTagName("IgnoreText");
	    	
	    	for(int j = 0; j < inner.getLength(); j++) {
	    		
	    		addIgnoredForMatch(inner.item(j).getTextContent());
	    	}
	    }

	}
	
	public WayfConfig()
	{
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
	 * 
	 * @param str
	 *            The string to lookup
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
	 * 
	 * @param s
	 *            The ignored tokens are passed as a single string, each separated by whitespace
	 */
	public void addIgnoredForMatch(String s) {

		ignoredForMatch.add(s.toLowerCase());
	}

	/**
	 * Returns the cacheDomain.
	 * 
	 * @return String
	 */
	public String getCacheDomain() {

		return cacheDomain;
	}

	/**
	 * Returns the cacheExpiration.
	 * 
	 * @return int
	 */
	public int getCacheExpiration() {

		return cacheExpiration;
	}

	/**
	 * Sets the cacheDomain.
	 * 
	 * @param cacheDomain
	 *            The cacheDomain to set
	 */
	public void setCacheDomain(String cacheDomain) {

		this.cacheDomain = cacheDomain;
	}

	/**
	 * Sets the cacheExpiration.
	 * 
	 * @param cacheExpiration
	 *            The cacheExpiration to set
	 */
	public void setCacheExpiration(int cacheExpiration) {

		this.cacheExpiration = cacheExpiration;
	}

}
