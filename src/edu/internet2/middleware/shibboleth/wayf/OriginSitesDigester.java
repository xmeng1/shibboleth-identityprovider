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

import javax.xml.parsers.SAXParser;

import org.xml.sax.XMLReader;

import edu.internet2.middleware.shibboleth.common.ServletDigester;

/**
 * @author Administrator
 *
 * To change this generated comment edit the template variable "typecomment":
 * Window>Preferences>Java>Templates.
 * To enable and disable the creation of type comments go to
 * Window>Preferences>Java>Code Generation.
 */
public class OriginSitesDigester extends ServletDigester {

	protected String originClass = "edu.internet2.middleware.shibboleth.wayf.Origin";
	protected String wayfDataClass = "edu.internet2.middleware.shibboleth.wayf.WayfOrigins";
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
	 * @param parser
	 */
	public OriginSitesDigester(SAXParser parser) {
		super(parser);
	}

	/**
	 * Constructor for OriginSitesDigester.
	 * @param reader
	 */
	public OriginSitesDigester(XMLReader reader) {
		super(reader);
	}

	/**
	* @see Digester#configure()
	*/
	protected void configure() {

		if (configured == true) {
			return;
		}
		//Create data container
		addObjectCreate("Sites", wayfDataClass);

		//Digest sites that are nested in a group
		addObjectCreate("Sites/SiteGroup", originSetClass);
		addSetNext("Sites/SiteGroup", "addOriginSet", originSetClass);
		addCallMethod("Sites/SiteGroup", "setName", 1);
		addCallParam("Sites/SiteGroup", 0, "Name");

		addObjectCreate("Sites/SiteGroup/OriginSite", originClass);
		addSetNext("Sites/SiteGroup/OriginSite", "addOrigin", originClass);
		addCallMethod("Sites/SiteGroup/OriginSite", "setName", 1);
		addCallParam("Sites/SiteGroup/OriginSite", 0, "Name");
		addSetProperties("Sites/SiteGroup/OriginSite");
		addCallMethod("Sites/SiteGroup/OriginSite/Alias", "addAlias", 0);
		addCallMethod("Sites/SiteGroup/OriginSite", "setHandleService", 1);
		addCallParam("Sites/SiteGroup/OriginSite/HandleService", 0, "Location");

		//Digest sites without nesting and add them to the default group
		addObjectCreate("Sites/OriginSite", originSetClass);
		addSetNext("Sites/OriginSite", "addOriginSet", originSetClass);
		addObjectCreate("Sites/OriginSite", originClass);
		addSetNext("Sites/OriginSite", "addOrigin", originClass);
		addCallMethod("Sites/OriginSite", "setName", 1);
		addCallParam("Sites/OriginSite", 0, "Name");
		addSetProperties("Sites/OriginSite");
		addCallMethod("Sites/OriginSite/Alias", "addAlias", 0);
		addCallMethod("Sites/OriginSite", "setHandleService", 1);
		addCallParam("Sites/OriginSite/HandleService", 0, "Location");

		configured = true;

	}

}
