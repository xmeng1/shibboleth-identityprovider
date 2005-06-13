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

import javax.xml.parsers.SAXParser;

import org.xml.sax.XMLReader;

import edu.internet2.middleware.shibboleth.common.ServletDigester;

/**
 * @author Administrator
 * 
 * To change this generated comment edit the template variable "typecomment": Window>Preferences>Java>Templates. To
 * enable and disable the creation of type comments go to Window>Preferences>Java>Code Generation.
 */
public class OriginSitesDigester extends ServletDigester {

	protected String originClass = "edu.internet2.middleware.shibboleth.wayf.Origin";
	protected String originSetClass = "edu.internet2.middleware.shibboleth.wayf.OriginSet";

	private boolean configured = false;

	/**
	 * Constructor for OriginSitesDigester.
	 */
	public OriginSitesDigester() {

		super();
	}

	/**
	 * Constructor for OriginSitesDigester.
	 * 
	 * @param parser
	 */
	public OriginSitesDigester(SAXParser parser) {

		super(parser);
	}

	/**
	 * Constructor for OriginSitesDigester.
	 * 
	 * @param reader
	 */
	public OriginSitesDigester(XMLReader reader) {

		super(reader);
	}

	/**
	 * @see Digester#configure()
	 */
	protected void configure() {

		if (configured == true) { return; }
		push(new WayfOrigins());
		// Digest sites that are nested in a group
		addObjectCreate("SiteGroup", originSetClass);
		addSetNext("SiteGroup", "addOriginSet", originSetClass);
		addCallMethod("SiteGroup", "setName", 1);
		addCallParam("SiteGroup", 0, "Name");

		addObjectCreate("SiteGroup/OriginSite", originClass);
		addSetNext("SiteGroup/OriginSite", "addOrigin", originClass);
		addCallMethod("SiteGroup/OriginSite", "setName", 1);
		addCallParam("SiteGroup/OriginSite", 0, "Name");
		addSetProperties("SiteGroup/OriginSite");
		addCallMethod("SiteGroup/OriginSite/Alias", "addAlias", 0);
		addCallMethod("SiteGroup/OriginSite", "setHandleService", 1);
		addCallParam("SiteGroup/OriginSite/HandleService", 0, "Location");

		// Digest sites without nesting and add them to the default group
		addObjectCreate("OriginSite", originSetClass);
		addSetNext("OriginSite", "addOriginSet", originSetClass);
		addObjectCreate("OriginSite", originClass);
		addSetNext("OriginSite", "addOrigin", originClass);
		addCallMethod("OriginSite", "setName", 1);
		addCallParam("OriginSite", 0, "Name");
		addSetProperties("OriginSite");
		addCallMethod("OriginSite/Alias", "addAlias", 0);
		addCallMethod("OriginSite", "setHandleService", 1);
		addCallParam("OriginSite/HandleService", 0, "Location");

		// Handle 1.3 Metadata
        addObjectCreate("EntitiesDescriptor", originSetClass);
		addSetNext("EntitiesDescriptor", "addOriginSet", originSetClass);
		addCallMethod("EntitiesDescriptor", "setName", 1);
		addCallParam("EntitiesDescriptor", 0, "Name");

		addObjectCreate("EntitiesDescriptor/EntityDescriptor", originClass);
		addSetNext("EntitiesDescriptor/EntityDescriptor", "addOrigin", originClass);

		addCallMethod("EntitiesDescriptor/EntityDescriptor", "setName", 1);
		addCallParam("EntitiesDescriptor/EntityDescriptor", 0, "entityID");

		addCallMethod("EntitiesDescriptor/EntityDescriptor/Organization/OrganizationName", "addAlias", 0);
		addCallMethod("EntitiesDescriptor/EntityDescriptor/Organization/OrganizationDisplayName", "addAlias", 0);
                
		addCallMethod("EntitiesDescriptor/EntityDescriptor/IDPSSODescriptor/SingleSignOnService", "setHandleService", 1);
		addCallParam("EntitiesDescriptor/EntityDescriptor/IDPSSODescriptor/SingleSignOnService", 0, "Location");
                                
		
		
		configured = true;

	}

}
