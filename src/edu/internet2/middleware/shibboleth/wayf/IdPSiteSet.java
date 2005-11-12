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

import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.apache.log4j.Logger;
import org.opensaml.XML;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.metadata.EntityDescriptor;
import edu.internet2.middleware.shibboleth.metadata.Metadata;
import edu.internet2.middleware.shibboleth.metadata.MetadataException;
import edu.internet2.middleware.shibboleth.metadata.MetadataProviderFactory;


/**
 * 
 * @author Rod Widdowson
 *
 * Represents a collection of related sites - usually a federation.  When the WAYF
 * looks to see which IdP sites to show, it trims the list so as to not show IdP's 
 * which do not trust the SP.
 *
 * This class is opaque outside this file.  The three static methods getSitesLists,
 * searchForMatchingOrigins and lookupIdP provide mechansims for accessing 
 * collections of IdPSiteSets.
 * 
 */

public class IdPSiteSet {
	
	private static Logger log = Logger.getLogger(IdPSiteSet.class.getName());

	private final Metadata metadata;
	private final String identifier;
	private final String displayName;
	
	public IdPSiteSet(Element el) throws ShibbolethConfigurationException {
		
	    identifier = el.getAttribute("identifier");
	    displayName = el.getAttribute("displayName");
	    
	    log.info("Loading Metadata for " + displayName);

	    try {
			metadata = MetadataProviderFactory.loadProvider(el);
	    } catch (MetadataException ex) {
	    	log.error("Could not parse " + displayName, ex);
	    	throw new ShibbolethConfigurationException("Could not parse " + displayName, ex);
	    }
	}
	
	/**
	 * The metadata representing this Set
	 */
	
	private Metadata getMetadata()
	{
		return metadata;
	}
	
	protected String getIdentifier() {
		return identifier;
	}

	private String getDisplayName() {
		return displayName;
	}

	/**
	 * We do not need to look at set if it doesn't know about the given SP.  However if
	 * no SP is given (as per 1.1) then we do need to look 
	 */

	private boolean containsSP(String SPName) {

		//
		// Deal with the case where we do *not* want to search by
		// SP (also handles the 1.1 case)
		//
		
		if ((SPName == null) || (SPName.length() == 0)) {
			return true;
		}
		
		EntityDescriptor e = metadata.lookup(SPName);
		
		if (e == null) {
			return false;
		}
		
		return (e.getSPSSODescriptor(XML.SAML11_PROTOCOL_ENUM) != null);
	}
	
	private EntityDescriptor IdPforName(String IdPName) {

		if ((IdPName == null) || (IdPName.length() == 0)) {
			return null;
		}
		
		return metadata.lookup(IdPName);
		
	}
	
	/**
	 * Iterate over all the sitesets and if they know about the SP add them to the 
	 * list and the list of lists.    
	 * 
	 * @param siteSets  All the site sets we know about
	 * 
	 * @param SPName The SP we are looking for (null or empty matches all sitesets)
	 * 
	 * @param siteLists If not null this is is populated with a set of sets of sites
	 *  
	 * @param sites.  If not Null this is populated with a set of sites.
	 */
	public static void getSiteLists(Collection /*<IdPSiteSet>*/ siteSets,
									String SPName,
									Collection /*<IdPSiteSetEntry>*/ siteLists,
									Collection /*<IdPSite>*/ sites) {
		//
		// By having siteLists and sites as parameters we only iterate over 
		// the metadata arrays once.
		//
		
		Iterator /*<IdPSiteSet>*/ it = siteSets.iterator();
		
		while (it.hasNext()) {
			IdPSiteSet set = (IdPSiteSet) it.next();
			
			if (set.containsSP(SPName)) {
				Collection c = IdPSite.getIdPSites(set.getMetadata());
				
				if (siteLists != null) {
					siteLists.add(new IdPSiteSetEntry(set.getDisplayName(),c));
				}
				
				if (sites != null) {
					sites.addAll(c);
				}
			}
		}
		
	}
	

	
	/**
	 * Give the set of siteSets, an SP name and a searchString, look for the name in all 
	 * the appropriate siteSets. 
	 *
	 */

	public static Collection /*<IdPSite>*/ seachForMatchingOrigins(Collection/*<IdPSiteSet>*/ siteSets, String SPName, String parameter, HandlerConfig config) {

		Collection/*<IdPSite>*/ result = null;
		Iterator/*<IdPSiteSet>*/ it = siteSets.iterator();
		
		while (it.hasNext()) {
			IdPSiteSet set = (IdPSiteSet) it.next();
			
			if (set.containsSP(SPName)) {
				Collection/*<IdPSite>*/ c = IdPSite.seachForMatchingOrigins(set.getMetadata(),parameter, config);
				
				if (result == null) {
					result = c;
				} else {
					result.addAll(c);
				}
			}
		}
		
		return result;
	}

	public static IdPSite IdPforSP(List /*<IdPSiteSet>*/ siteSets, String IdPName, String SPName) {

		Iterator /*<IdPSiteSet>*/ it = siteSets.iterator();
		
		while (it.hasNext()) {
			IdPSiteSet set = (IdPSiteSet) it.next();
			
			if (set.containsSP(SPName)) {
				EntityDescriptor e = set.IdPforName(IdPName);
				
				if (e != null) {
					return new IdPSite(e);
				}
			}
		}
		
		return null;
	}
}

