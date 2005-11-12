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
 * Class used by the DiscoveryServiceHandler to handle run time behaviour 
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */

public class HandlerConfig {

	private static final Logger log = Logger.getLogger(HandlerConfig.class.getName());
	public final static String configNameSpace = "urn:mace:shibboleth:wayf:config:1.0"; 

	private final HashSet ignoredForMatch;
	private final int cacheExpiration;
	private final String cacheDomain;
	private final String jspFile;
	private final String errorJspFile;
	private final boolean provideListOfLists;  // defaults false below
	private final boolean provideList;         // defaults true below
	private final boolean lookupSp;            // defaults true below 
	private final int handleCookie;
	//
	// hacked enum
	//
	public final static int ALWAYS_FOLLOW_COOKIE = 9;
	public final static int FOLLOW_SINGLE_COOKIE = 10;
	public final static int NEVER_FOLLOW_COOKIE = 11;
	public final static int CLEAR_COOKIE = 12;

	public HandlerConfig() {
		//
		// 'Sensible' default values
		//
		cacheExpiration = 604800;
		cacheDomain = "";
		jspFile = "/wayf.jsp";
		errorJspFile = "/wayfError.jsp";
		provideList = true;
		provideListOfLists = false;
		lookupSp = true;
		handleCookie = NEVER_FOLLOW_COOKIE;
		ignoredForMatch = new HashSet();	
	}
	
	
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
	
	public HandlerConfig(Element config, HandlerConfig defaultValue) throws ShibbolethConfigurationException {
	    
	    log.debug("Loading global configuration properties.");

	    String attribute   = config.getAttribute("cacheDomain");
	    if ((attribute != null) && (attribute != "")) {
    		cacheDomain = attribute;
	    } else {
	    	cacheDomain = defaultValue.cacheDomain;
	    }
	    	
	    attribute = config.getAttribute("cacheExpiration");
	    if ((attribute != null) && (attribute != "")) {
	    	
	    	try {

	    		cacheExpiration = Integer.parseInt(attribute);
	    	} catch (NumberFormatException ex) {
	    		
				log.error("Invalid CacheExpiration value - " + attribute);
	    		throw new ShibbolethConfigurationException("Invalid CacheExpiration value - " + attribute, ex);
	    		
	    	}
	    } else {
	    	cacheExpiration = defaultValue.cacheExpiration;
	    }

	    NodeList list = config.getElementsByTagName("SearchIgnore");
	    
	    if (list.getLength() == 0) {
	    	
	    	ignoredForMatch = defaultValue.ignoredForMatch;

	    } else { 
	    	
	    	ignoredForMatch = new HashSet();	
		    
	    	for (int i = 0; i < list.getLength(); i++ ) {
		    	
		    	NodeList inner = ((Element) list.item(i)).getElementsByTagName("IgnoreText");
		    	
		    	for(int j = 0; j < inner.getLength(); j++) {
		    		
		    		addIgnoredForMatch(inner.item(j).getTextContent());
		    	}
		    }
	    }

	    attribute = config.getAttribute("jspFile");
		if (attribute != null && !attribute.equals("")) {
			jspFile = attribute;
		} else {
			jspFile = defaultValue.jspFile;
		}
		
		attribute = config.getAttribute("errorJspFile");
		if (attribute != null && !attribute.equals("")) {
			errorJspFile = attribute;
		} else {
			errorJspFile = defaultValue.errorJspFile;
		}
		
		attribute = ((Element) config).getAttribute("provideList");
		if (attribute != null && !attribute.equals("")) {
			provideList = Boolean.valueOf(attribute).booleanValue();
		} else { 
			provideList = defaultValue.provideList;
		}

		attribute = ((Element) config).getAttribute("provideListOfList");
		if (attribute != null && !attribute.equals("")) {
			provideListOfLists = Boolean.valueOf(attribute).booleanValue();
		} else {
			provideListOfLists = defaultValue.provideListOfLists;
		}
		
		attribute = ((Element) config).getAttribute("showUnusableIdPs");
		if (attribute != null && !attribute.equals("")) {
			lookupSp = !Boolean.valueOf(attribute).booleanValue();
		} else {
			lookupSp = defaultValue.lookupSp;
		}

		attribute = ((Element) config).getAttribute("handleCookie");
		if (attribute == null || attribute.equals("")) {
			handleCookie = defaultValue.handleCookie;
		} else if (attribute.equalsIgnoreCase("alwaysfollow")) {
			handleCookie = ALWAYS_FOLLOW_COOKIE;
		} else if (attribute.equalsIgnoreCase("followsingle")) {
			handleCookie = FOLLOW_SINGLE_COOKIE;
		} else if (attribute.equalsIgnoreCase("neverfollow")) {
			handleCookie = NEVER_FOLLOW_COOKIE;
		} else if (attribute.equalsIgnoreCase("clearcookie")) {
			handleCookie = CLEAR_COOKIE;
		} else {
			
			log.error("Invalid value " + attribute + " to HandleCookie");
			throw new ShibbolethConfigurationException("Invalid value " + attribute + " to HandleCookie");
		}	
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
	private void addIgnoredForMatch(String s) {

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
	
	public String getJspFile() {
		return jspFile;
	}
	
	public String getErrorJspFile() {
		return errorJspFile;
	}
	
	public boolean getProvideListOfLists() {
		return provideListOfLists;
	}
	
	public boolean getProvideList() {
		return provideList;
	}
	
	public boolean getLookupSp() {	
		return lookupSp;  
	}
	
	public int getHandleCookie() {	
		return handleCookie;  
	}
}
