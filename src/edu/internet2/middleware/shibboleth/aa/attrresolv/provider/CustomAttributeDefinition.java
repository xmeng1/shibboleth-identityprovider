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

import java.security.Principal;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeDefinitionPlugIn;
import edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugIn;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugInException;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolverAttribute;

/**
 * 
 * Wrapper class for custom <code>AttributeDefinitionPlugIn</code> implementations.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 *
 */
public class CustomAttributeDefinition implements ResolutionPlugIn, AttributeDefinitionPlugIn {

	private static Logger log = Logger.getLogger(CustomAttributeDefinition.class.getName());
	private AttributeDefinitionPlugIn custom;

	public CustomAttributeDefinition(Element e) throws ResolutionPlugInException {
		if (!e.getTagName().equals("CustomAttributeDefinition")) {
			log.error("Incorrect attribute definition configuration: expected <CustomAttributeDefinition> .");
			throw new ResolutionPlugInException("Failed to initialize Attribute Definition PlugIn.");
		}

		String className = e.getAttribute("class");
		if (className == null || className.equals("")) {
			log.error("Custom Attribute Definition requires specification of the attribute \"class\".");
			throw new ResolutionPlugInException("Failed to initialize Attribute Definition PlugIn.");
		} else {
			try {
				Class[] params = { Class.forName("org.w3c.dom.Element"), };
				Object[] passElement = { e };
				custom =
					(AttributeDefinitionPlugIn) Class.forName(className).getConstructor(params).newInstance(
						passElement);
			} catch (Exception loaderException) {
				log.error(
					"Failed to load Custom Attribute Definition PlugIn implementation class: "
						+ loaderException.getMessage());
				throw new ResolutionPlugInException("Failed to initialize Attribute Definition PlugIn.");
			}
		}
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeDefinitionPlugIn#resolve(edu.internet2.middleware.shibboleth.aa.attrresolv.ResolverAttribute, java.security.Principal, java.lang.String, edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies)
	 */
	public void resolve(ResolverAttribute attribute, Principal principal, String requester, Dependencies depends)
		throws ResolutionPlugInException {
		custom.resolve(attribute, principal, requester, depends);
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.BaseResolutionPlugIn#getId()
	 */
	public String getId() {
		return custom.getId();
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.provider.BaseResolutionPlugIn#getTTL()
	 */
	public long getTTL() {
		return custom.getTTL();
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeDefinitionPlugIn#getAttributeDefinitionDependencyIds()
	 */
	public String[] getAttributeDefinitionDependencyIds() {
		return custom.getAttributeDefinitionDependencyIds();
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeDefinitionPlugIn#getDataConnectorDependencyIds()
	 */
	public String[] getDataConnectorDependencyIds() {
		return custom.getDataConnectorDependencyIds();
	}

}
