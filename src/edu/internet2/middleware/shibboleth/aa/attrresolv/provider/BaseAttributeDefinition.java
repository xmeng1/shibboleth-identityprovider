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
 
package edu.internet2.middleware.shibboleth.aa.attrresolv.provider;

import java.util.HashSet;
import java.util.Set;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeDefinitionPlugIn;
import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugInException;

/**
 * Base class for Attribute Definition PlugIns.  Provides basic functionality such as 
 * dependency mapping.  Subclasses must provide resolution logic.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */

public abstract class BaseAttributeDefinition extends BaseResolutionPlugIn implements AttributeDefinitionPlugIn {
	
	/** The time, in seconds, for which attribute created from this definition should be valid. */
	protected long lifeTime = -1;
	
	private static Logger log = Logger.getLogger(BaseAttributeDefinition.class.getName());
	protected Set connectorDependencyIds = new HashSet();
	protected Set attributeDependencyIds = new HashSet();

	protected BaseAttributeDefinition(Element e) throws ResolutionPlugInException {

		super(e);

		String lifeTimeSpec = e.getAttribute("lifeTime");
		if (lifeTimeSpec != null && !lifeTimeSpec.equals("")) {
			try {
				lifeTime = Long.valueOf(lifeTimeSpec).longValue();
				log.debug("Explicit lifetime set for attribute (" + getId() + ").  Lifetime: (" + lifeTime + ").");
			} catch (NumberFormatException nfe) {
				log.error("Bad value for attribute (lifeTime) for Attribute Definition (" + getId() + ").");
			}
		}

		NodeList connectorNodes = e.getElementsByTagNameNS(AttributeResolver.resolverNamespace, "DataConnectorDependency");

		for (int i = 0; connectorNodes.getLength() > i; i++) {
			Element connector = (Element) connectorNodes.item(i);
			String connectorName = connector.getAttribute("requires");
			if (connectorName != null && !connectorName.equals("")) {
				addDataConnectorDependencyId(connectorName);
			} else {
				log.error("Data Connector dependency must be accomanied by a \"requires\" attribute.");
				throw new ResolutionPlugInException("Failed to initialize Attribute PlugIn.");
			}
		}

		NodeList attributeNodes = e.getElementsByTagNameNS(AttributeResolver.resolverNamespace, "AttributeDependency");
		for (int i = 0; attributeNodes.getLength() > i; i++) {
			Element attribute = (Element) attributeNodes.item(i);
			String attributeName = attribute.getAttribute("requires");
			if (attributeName != null && !attributeName.equals("")) {
				addAttributeDefinitionDependencyId(attributeName);
			} else {
				log.error("Attribute Definition dependency must be accomanied by a \"requires\" attribute.");
				throw new ResolutionPlugInException("Failed to initialize Attribute PlugIn.");
			}
		}

		if (connectorNodes.getLength() == 0 && attributeNodes.getLength() == 0) {
			log.warn("Attribute " + getId() + " has no registered dependencies.");
		}

	}

	protected void addDataConnectorDependencyId(String id) {
		connectorDependencyIds.add(id);
	}

	protected void addAttributeDefinitionDependencyId(String id) {
		attributeDependencyIds.add(id);
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeDefinitionPlugIn#getAttributeDependencyIds()
	 */
	public String[] getAttributeDefinitionDependencyIds() {
		return (String[]) attributeDependencyIds.toArray(new String[0]);
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeDefinitionPlugIn#getConnectorDependencyIds()
	 */
	public String[] getDataConnectorDependencyIds() {
		return (String[]) connectorDependencyIds.toArray(new String[0]);
	}

}
