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
import java.util.Properties;

import javax.naming.CommunicationException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver;
import edu.internet2.middleware.shibboleth.aa.attrresolv.DataConnectorPlugIn;
import edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugInException;

/**
 * <code>DataConnectorPlugIn</code> implementation that utilizes a user-specified JNDI 
 * <code>DirContext</code> to retrieve attribute data.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 *
 */
public class JNDIDirectoryDataConnector extends BaseDataConnector implements DataConnectorPlugIn {

	private static Logger log = Logger.getLogger(JNDIDirectoryDataConnector.class.getName());
	protected String searchFilter;
	protected Properties properties;
	protected SearchControls controls;
    protected String failover = null;

    /**
     * Constructs a DataConnector based on DOM configuration.
     * 
     * @param e a &lt;JNDIDirectoryDataConnector /&gt; DOM Element as specified by 
     * urn:mace:shibboleth:resolver:1.0
     * 
     * @throws ResolutionPlugInException if the PlugIn cannot be initialized
     */
	public JNDIDirectoryDataConnector(Element e) throws ResolutionPlugInException {

		super(e);
        
		NodeList searchNodes = e.getElementsByTagNameNS(AttributeResolver.resolverNamespace, "Search");
		if (searchNodes.getLength() != 1) {
			log.error("JNDI Directory Data Connector requires a \"Search\" specification.");
			throw new ResolutionPlugInException("JNDI Directory Data Connector requires a \"Search\" specification.");
		}

		String searchFilterSpec = ((Element) searchNodes.item(0)).getAttribute("filter");
		if (searchFilterSpec != null && !searchFilterSpec.equals("")) {
			searchFilter = searchFilterSpec;
			log.debug("Search Filter: (" + searchFilter + ").");
		} else {
			log.error("Search spec requires a filter attribute.");
			throw new ResolutionPlugInException("Search spec requires a filter attribute.");
		}

		defineSearchControls(((Element) searchNodes.item(0)));

		NodeList propertyNodes = e.getElementsByTagNameNS(AttributeResolver.resolverNamespace, "Property");
		properties = System.getProperties();
		for (int i = 0; propertyNodes.getLength() > i; i++) {
			Element property = (Element) propertyNodes.item(i);
			String propName = property.getAttribute("name");
			String propValue = property.getAttribute("value");

			if (propName != null && !propName.equals("") && propValue != null && !propValue.equals("")) {
				properties.setProperty(propName, propValue);
				log.debug("Property: (" + propName + ").");
				log.debug("   Value: (" + propValue + ").");
			} else {
				log.error("Property is malformed.");
				throw new ResolutionPlugInException("Property is malformed.");
			}
		}

        //Fail-fast connection test
		InitialDirContext context = null;
		try {
			context = new InitialDirContext(properties);
			log.debug("JNDI Directory context activated.");
			
		} catch (NamingException e1) {
			log.error("Failed to startup directory context: " + e1);
			throw new ResolutionPlugInException("Failed to startup directory context.");
		} finally {
			try {
				if (context != null) {
					context.close();
				}
			} catch (NamingException ne) {
				log.error("An error occured while closing the JNDI context: " + e);
			}

		}
	}

    /**
     * Create JNDI search controls based on DOM configuration
     * @param searchNode a &lt;Controls /&gt; DOM Element as specified by 
     * urn:mace:shibboleth:resolver:1.0
     */
	protected void defineSearchControls(Element searchNode) {

		controls = new SearchControls();

		NodeList controlNodes = searchNode.getElementsByTagNameNS(AttributeResolver.resolverNamespace, "Controls");
		if (controlNodes.getLength() < 1) {
			log.debug("No Search Control spec found.");
		} else {
			if (controlNodes.getLength() > 1) {
				log.error("Found multiple Search Control specs for a Connector.  Ignoring all but the first.");
			}

			String searchScopeSpec = ((Element) controlNodes.item(0)).getAttribute("searchScope");
			if (searchScopeSpec != null && !searchScopeSpec.equals("")) {
				if (searchScopeSpec.equals("OBJECT_SCOPE")) {
					controls.setSearchScope(SearchControls.OBJECT_SCOPE);
				} else if (searchScopeSpec.equals("ONELEVEL_SCOPE")) {
					controls.setSearchScope(SearchControls.ONELEVEL_SCOPE);
				} else if (searchScopeSpec.equals("SUBTREE_SCOPE")) {
					controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
				} else {
					try {
						controls.setSearchScope(Integer.parseInt(searchScopeSpec));
					} catch (NumberFormatException nfe) {
						log.error("Control spec included an invalid (searchScope) attribute value.");
					}
				}
			}

			String timeLimitSpec = ((Element) controlNodes.item(0)).getAttribute("timeLimit");
			if (timeLimitSpec != null && !timeLimitSpec.equals("")) {
				try {
					controls.setTimeLimit(Integer.parseInt(timeLimitSpec));
				} catch (NumberFormatException nfe) {
					log.error("Control spec included an invalid (timeLimit) attribute value.");
				}
			}

			String returningObjectsSpec = ((Element) controlNodes.item(0)).getAttribute("returningObjects");
			if (returningObjectsSpec != null && !returningObjectsSpec.equals("")) {
				controls.setReturningObjFlag(new Boolean(returningObjectsSpec).booleanValue());
			}

			String linkDereferencingSpec = ((Element) controlNodes.item(0)).getAttribute("linkDereferencing");
			if (linkDereferencingSpec != null && !linkDereferencingSpec.equals("")) {
				if (linkDereferencingSpec != null && !linkDereferencingSpec.equals("")) {
					controls.setDerefLinkFlag(new Boolean(linkDereferencingSpec).booleanValue());
				}
			}

			String countLimitSpec = ((Element) controlNodes.item(0)).getAttribute("countLimit");
			if (countLimitSpec != null && !countLimitSpec.equals("")) {
				try {
					controls.setCountLimit(Long.parseLong(countLimitSpec));
				} catch (NumberFormatException nfe) {
					log.error("Control spec included an invalid (countLimit) attribute value.");
				}
			}
		}

		if (log.isDebugEnabled()) {
			log.debug("Search Control (searchScope): " + controls.getSearchScope());
			log.debug("Search Control (timeLimit): " + controls.getTimeLimit());
			log.debug("Search Control (returningObjects): " + controls.getReturningObjFlag());
			log.debug("Search Control (linkDereferencing): " + controls.getDerefLinkFlag());
			log.debug("Search Control (countLimit): " + controls.getCountLimit());
		}
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.DataConnectorPlugIn#resolve(java.security.Principal)
	 */
	public Attributes resolve(Principal principal, String requester, Dependencies depends)
		throws ResolutionPlugInException {

		InitialDirContext context = null;
		try {
			context = new InitialDirContext(properties);
			NamingEnumeration enum = null;

			try {
				enum = context.search("", searchFilter.replaceAll("%PRINCIPAL%", principal.getName()), controls);
			} catch (CommunicationException e) {
				log.debug(e);
				log.warn(
					"Encountered a connection problem while querying for attributes.  Re-initializing JNDI context and retrying...");
				context = new InitialDirContext(context.getEnvironment());
				enum = context.search("", searchFilter.replaceAll("%PRINCIPAL%", principal.getName()), controls);
			}

			if (enum == null || !enum.hasMore()) {
				log.error("Could not locate a principal with the name (" + principal.getName() + ").");
				throw new ResolutionPlugInException("No data available for this principal.");
			}

			SearchResult result = (SearchResult) enum.next();
			Attributes attributes = result.getAttributes();

			if (enum.hasMore()) {
				log.error("Unable to disambiguate date for principal (" + principal.getName() + ") in search.");
				throw new ResolutionPlugInException("Cannot disambiguate data for this principal.");
			}

			return attributes;

		} catch (NamingException e) {
			log.error(
				"An error occurred while retieving data for principal ("
					+ principal.getName()
					+ ") :"
					+ e.getMessage());
			throw new ResolutionPlugInException("Error retrieving data for principal.");
		} finally {
			try {
				if (context != null) {
					context.close();
				}
			} catch (NamingException e) {
				log.error("An error occured while closing the JNDI context: " + e);
			}
		}
	}
}
