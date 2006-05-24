/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.] Licensed under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in
 * writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.aa.attrresolv;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.aa.attrresolv.provider.CompositeAttributeDefinition;
import edu.internet2.middleware.shibboleth.aa.attrresolv.provider.CustomAttributeDefinition;
import edu.internet2.middleware.shibboleth.aa.attrresolv.provider.CustomDataConnector;
import edu.internet2.middleware.shibboleth.aa.attrresolv.provider.FormattedAttributeDefinition;
import edu.internet2.middleware.shibboleth.aa.attrresolv.provider.JDBCDataConnector;
import edu.internet2.middleware.shibboleth.aa.attrresolv.provider.JNDIDirectoryDataConnector;
import edu.internet2.middleware.shibboleth.aa.attrresolv.provider.MappedAttributeDefinition;
import edu.internet2.middleware.shibboleth.aa.attrresolv.provider.PersistentIDAttributeDefinition;
import edu.internet2.middleware.shibboleth.aa.attrresolv.provider.RegExAttributeDefinition;
import edu.internet2.middleware.shibboleth.aa.attrresolv.provider.SAML2PersistentID;
import edu.internet2.middleware.shibboleth.aa.attrresolv.provider.ScriptletAttributeDefinition;
import edu.internet2.middleware.shibboleth.aa.attrresolv.provider.SimpleAttributeDefinition;
import edu.internet2.middleware.shibboleth.aa.attrresolv.provider.StaticDataConnector;

/**
 * Factory that instanciates Resolution PlugIns based on Resolver configuration elements.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */

public class ResolutionPlugInFactory {

	private static Logger log = Logger.getLogger(ResolutionPlugInFactory.class.getName());

	public static ResolutionPlugIn createPlugIn(Element e) throws AttributeResolverException {

		if (e.getTagName().equals("CustomDataConnector")) { return new CustomDataConnector(e); }

		if (e.getTagName().equals("CustomAttributeDefinition")) { return new CustomAttributeDefinition(e); }

		if (e.getTagName().equals("SimpleAttributeDefinition")) { return new SimpleAttributeDefinition(e); }

		if (e.getTagName().equals("SAML2PersistentID")) { return new SAML2PersistentID(e); }

		if (e.getTagName().equals("PersistentIDAttributeDefinition")) { return new PersistentIDAttributeDefinition(e); }

		if (e.getTagName().equals("JNDIDirectoryDataConnector")) { return new JNDIDirectoryDataConnector(e); }

		if (e.getTagName().equals("JDBCDataConnector")) { return new JDBCDataConnector(e); }

		if (e.getTagName().equals("StaticDataConnector")) { return new StaticDataConnector(e); }

		if (e.getTagName().equals("RegExAttributeDefinition")) { return new RegExAttributeDefinition(e); }

		if (e.getTagName().equals("FormattedAttributeDefinition")) { return new FormattedAttributeDefinition(e); }

		if (e.getTagName().equals("CompositeAttributeDefinition")) { return new CompositeAttributeDefinition(e); }

		if (e.getTagName().equals("MappedAttributeDefinition")) { return new MappedAttributeDefinition(e); }
		
		if (e.getTagName().equals("ScriptletAttributeDefinition")) { return new ScriptletAttributeDefinition(e); }

		log.error("Unrecognized PlugIn type: " + e.getTagName());
		throw new AttributeResolverException("Failed to initialize PlugIn.");
	}

}
