/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met: Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials
 * provided with the distribution, if any, must include the following acknowledgment: "This product includes software
 * developed by the University Corporation for Advanced Internet Development <http://www.ucaid.edu>Internet2 Project.
 * Alternately, this acknowledegement may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear. Neither the name of Shibboleth nor the names of its contributors, nor Internet2, nor
 * the University Corporation for Advanced Internet Development, Inc., nor UCAID may be used to endorse or promote
 * products derived from this software without specific prior written permission. For written permission, please contact
 * shibboleth@shibboleth.org Products derived from this software may not be called Shibboleth, Internet2, UCAID, or the
 * University Corporation for Advanced Internet Development, nor may Shibboleth appear in their name, without prior
 * written permission of the University Corporation for Advanced Internet Development. THIS SOFTWARE IS PROVIDED BY THE
 * COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE
 * DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE. IN NO
 * EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC.
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.aa.attrresolv.provider;

import java.io.IOException;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Properties;
import java.util.Set;

import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.StartTlsRequest;
import javax.naming.ldap.StartTlsResponse;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509KeyManager;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver;
import edu.internet2.middleware.shibboleth.aa.attrresolv.DataConnectorPlugIn;
import edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugInException;
import edu.internet2.middleware.shibboleth.common.Credential;
import edu.internet2.middleware.shibboleth.common.Credentials;

/**
 * <code>DataConnectorPlugIn</code> implementation that utilizes a user-specified JNDI <code>DirContext</code> to
 * retrieve attribute data.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */
public class JNDIDirectoryDataConnector extends BaseDataConnector implements DataConnectorPlugIn {

	private static Logger log = Logger.getLogger(JNDIDirectoryDataConnector.class.getName());
	protected String searchFilter;
	protected Properties properties;
	protected SearchControls controls;
	protected boolean mergeMultiResults = false;
	protected boolean startTls = false;
	boolean useExternalAuth = false;
	private SSLSocketFactory sslsf;

	/**
	 * Constructs a DataConnector based on DOM configuration.
	 * 
	 * @param e
	 *            a &lt;JNDIDirectoryDataConnector /&gt; DOM Element as specified by urn:mace:shibboleth:resolver:1.0
	 * @throws ResolutionPlugInException
	 *             if the PlugIn cannot be initialized
	 */
	public JNDIDirectoryDataConnector(Element e) throws ResolutionPlugInException {

		super(e);

		// Decide if we are using starttls
		String tlsAttribute = e.getAttribute("useStartTls");
		if (tlsAttribute != null && tlsAttribute.equalsIgnoreCase("TRUE")) {
			startTls = true;
			log.debug("Start TLS support enabled for connector.");
		}

		// Do we merge the attributes in the event of multiple results from a search?
		String mergeMultiResultsAttrib = e.getAttribute("mergeMultipleResults");
		if (mergeMultiResultsAttrib != null && mergeMultiResultsAttrib.equalsIgnoreCase("TRUE")) {
			mergeMultiResults = true;
			log.debug("Multiple searcg result merging enabled for connector.");
		}

		// Determine the search filter and controls
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

		// Load JNDI properties
		NodeList propertyNodes = e.getElementsByTagNameNS(AttributeResolver.resolverNamespace, "Property");
		properties = new Properties(System.getProperties());
		for (int i = 0; propertyNodes.getLength() > i; i++) {
			Element property = (Element) propertyNodes.item(i);
			String propName = property.getAttribute("name");
			String propValue = property.getAttribute("value");

			log.debug("Property: (" + propName + ").");
			log.debug("   Value: (" + propValue + ").");

			if (propName == null || propName.equals("")) {
				log.error("Property (" + propName + ") is malformed.  Connot accept empty property name.");
				throw new ResolutionPlugInException("Property is malformed.");
			} else if (propValue == null || propValue.equals("")) {
				log.error("Property (" + propName + ") is malformed.  Cannot accept empty property value.");
				throw new ResolutionPlugInException("Property is malformed.");
			} else {
				properties.setProperty(propName, propValue);
			}
		}

		// Fail-fast connection test
		InitialDirContext context = null;
		try {
			if (!startTls) {
				try {
					log.debug("Attempting to connect to JNDI directory source as a sanity check.");
					context = initConnection();
				} catch (IOException ioe) {
					log.error("Failed to startup directory context: " + ioe);
					throw new ResolutionPlugInException("Failed to startup directory context.");
				}
			} else {
				// UGLY!
				// We can't do SASL EXTERNAL auth until we have a TLS session
				// So, we need to take this out of the environment and then stick it back in later
				if ("EXTERNAL".equals(properties.getProperty(Context.SECURITY_AUTHENTICATION))) {
					useExternalAuth = true;
					properties.remove(Context.SECURITY_AUTHENTICATION);
				}

				// If TLS credentials were supplied, load them and setup a KeyManager
				KeyManager keyManager = null;
				NodeList credNodes = e.getElementsByTagNameNS(Credentials.credentialsNamespace, "Credential");
				if (credNodes.getLength() > 0) {
					log.debug("JNDI Directory Data Connector has a \"Credential\" specification.  "
							+ "Loading credential...");
					Credentials credentials = new Credentials((Element) credNodes.item(0));
					Credential clientCred = credentials.getCredential();
					if (clientCred == null) {
						log.error("No credentials were loaded.");
						throw new ResolutionPlugInException("Error loading credential.");
					}
					keyManager = new KeyManagerImpl(clientCred.getPrivateKey(), clientCred.getX509CertificateChain());
				}

				try {
					// Setup a customized SSL socket factory that uses our implementation of KeyManager
					// This factory will be used for all subsequent TLS negotiation
					SSLContext sslc = SSLContext.getInstance("TLS");
					sslc.init(new KeyManager[]{keyManager}, null, new SecureRandom());
					sslsf = sslc.getSocketFactory();

					log.debug("Attempting to connect to JNDI directory source as a sanity check.");
					initConnection();
				} catch (GeneralSecurityException gse) {
					log.error("Failed to startup directory context.  Error creating SSL socket: " + gse);
					throw new ResolutionPlugInException("Failed to startup directory context.");

				} catch (IOException ioe) {
					log.error("Failed to startup directory context.  Error negotiating Start TLS: " + ioe);
					throw new ResolutionPlugInException("Failed to startup directory context.");
				}
			}

			log.debug("JNDI Directory context activated.");

		} catch (NamingException ne) {
			log.error("Failed to startup directory context: " + ne);
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
	 * 
	 * @param searchNode
	 *            a &lt;Controls /&gt; DOM Element as specified by urn:mace:shibboleth:resolver:1.0
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
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.DataConnectorPlugIn#resolve(java.security.Principal,
	 *      java.lang.String, java.lang.String, edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies)
	 */
	public Attributes resolve(Principal principal, String requester, String responder, Dependencies depends)
			throws ResolutionPlugInException {

		InitialDirContext context = null;
		NamingEnumeration nEnumeration = null;
		String populatedSearch = searchFilter.replaceAll("%PRINCIPAL%", principal.getName());
		try {
			try {
				context = initConnection();
				nEnumeration = context.search("", populatedSearch, controls);

				// If we get a failure during the init or query, attempt once to re-establish the connection
			} catch (CommunicationException e) {
				log.debug(e);
				log.warn("Encountered a connection problem while querying for attributes.  Re-initializing "
						+ "JNDI context and retrying...");
				context = initConnection();
				nEnumeration = context.search("", populatedSearch, controls);
			} catch (IOException e) {
				log.debug(e);
				log.warn("Encountered a connection problem while querying for attributes.  Re-initializing "
						+ "JNDI context and retrying...");
				context = initConnection();
				nEnumeration = context.search("", populatedSearch, controls);
			}

			if (nEnumeration == null || !nEnumeration.hasMore()) {
				log.error("Could not locate a principal with the name (" + principal.getName() + ").");
				throw new ResolutionPlugInException("No data available for this principal.");
			}

			SearchResult result = (SearchResult) nEnumeration.next();
			Attributes attributes = result.getAttributes();

			if (!mergeMultiResults) {
				if (nEnumeration.hasMore()) {
					log.error("Multiple results returned from filter " + searchFilter + " for principal " + principal
							+ ", only one expected.");
					throw new ResolutionPlugInException("Multiple results returned when only one expected.");
				}
			} else {
				log.debug("Multiple results returned by filter " + populatedSearch
						+ " merging attributes from each result");
				attributes = mergeResults(nEnumeration, attributes);
			}

			// For Sun's ldap provider only, construct the dn of the returned entry and manually add that as an
			// attribute
			if (context.getEnvironment().get(Context.INITIAL_CONTEXT_FACTORY)
					.equals("com.sun.jndi.ldap.LdapCtxFactory")) {
				BasicAttribute dn = new BasicAttribute("dn", result.getName() + "," + context.getNameInNamespace());
				attributes.put(dn);
			}

			return attributes;

		} catch (NamingException e) {
			log.error("An error occurred while retieving data for principal (" + principal.getName() + ") :"
					+ e.getMessage());
			throw new ResolutionPlugInException("Error retrieving data for principal.");
		} catch (IOException e) {
			log.error("An error occurred while retieving data for principal (" + principal.getName() + ") :"
					+ e.getMessage());
			throw new ResolutionPlugInException("Error retrieving data for principal.");

		} finally {
			try {
				if (context != null) {
					context.close();
				}
				if (nEnumeration != null) {
					nEnumeration.close();
				}
			} catch (NamingException e) {
				log.error("An error occured while closing the JNDI context: " + e);
			}
		}
	}

	/**
	 * Merges the attributes found in each result and a base Attributes object. If a named attribute appears in more
	 * than one result it's values are added to any existing values already in the given Attributes object. Duplicate
	 * attribute values are eliminated.
	 * 
	 * @param searchResults
	 *            the search result
	 * @param attributes
	 *            the container to add the attributes from the search result to (may already contain attributes)
	 * @return all the attributes and values merged from search results and initial attributes set
	 * @throws NamingException
	 *             thrown if there is a problem reading result data
	 */
	private Attributes mergeResults(NamingEnumeration searchResults, Attributes attributes) throws NamingException {

		HashMap attributeMap = new HashMap();

		mergeAttributes(attributeMap, attributes);

		SearchResult result;
		while (searchResults.hasMore()) {
			result = (SearchResult) searchResults.next();
			mergeAttributes(attributeMap, result.getAttributes());
		}

		Attributes mergedAttribs = new BasicAttributes(false);
		Attribute mergedAttrib;
		Iterator attribNames = attributeMap.keySet().iterator();
		Iterator attribValues;
		String attribName;
		while (attribNames.hasNext()) {
			attribName = (String) attribNames.next();
			mergedAttrib = new BasicAttribute(attribName, false);
			Set valueSet = (Set) attributeMap.get(attribName);
			attribValues = valueSet.iterator();
			while (attribValues.hasNext()) {
				mergedAttrib.add(attribValues.next());
			}
			mergedAttribs.put(mergedAttrib);
		}

		return mergedAttribs;
	}

	/**
	 * Merges a given collection of Attributes into an existing collection.
	 * 
	 * @param attributeMap
	 *            existing collection of attribute data
	 * @param attributes
	 *            collection of attribute data to be merged in
	 * @throws NamingException
	 *             thrown if there is a problem getting attribute information
	 */
	private void mergeAttributes(HashMap attributeMap, Attributes attributes) throws NamingException {

		if (attributes == null || attributes.size() <= 0) {
			// In case the search result this came from was empty
			return;
		}

		HashSet valueSet;
		NamingEnumeration baseAttribs = attributes.getAll();
		Attribute baseAttrib;
		while (baseAttribs.hasMore()) {
			baseAttrib = (Attribute) baseAttribs.next();
			if (attributeMap.containsKey(baseAttrib.getID())) {
				valueSet = (HashSet) attributeMap.get(baseAttrib.getID());
			} else {
				valueSet = new HashSet();
			}
			for (int i = 0; i < baseAttrib.size(); i++) {
				valueSet.add(baseAttrib.get(i));
			}
			attributeMap.put(baseAttrib.getID(), valueSet);
		}
	}

	private InitialDirContext initConnection() throws NamingException, IOException, ResolutionPlugInException {

		InitialDirContext context;
		if (!startTls) {
			context = new InitialDirContext(properties);

		} else {
			context = new InitialLdapContext(properties, null);
			if (!(context instanceof LdapContext)) {
				log.error("Directory context does not appear to be an implementation of LdapContext.  "
						+ "This is required for startTls.");
				throw new ResolutionPlugInException("Start TLS is only supported for implementations of LdapContext.");
			}
			StartTlsResponse tls = (StartTlsResponse) ((LdapContext) context).extendedOperation(new StartTlsRequest());
			tls.negotiate(sslsf);
			if (useExternalAuth) {
				context.addToEnvironment(Context.SECURITY_AUTHENTICATION, "EXTERNAL");
			}
		}
		return context;
	}
}

/**
 * Implementation of <code>X509KeyManager</code> that always uses a hard-coded client certificate.
 */

class KeyManagerImpl implements X509KeyManager {

	private PrivateKey key;
	private X509Certificate[] chain;

	KeyManagerImpl(PrivateKey key, X509Certificate[] chain) {

		this.key = key;
		this.chain = chain;
	}

	public String[] getClientAliases(String arg0, Principal[] arg1) {

		return new String[]{"default"};
	}

	public String chooseClientAlias(String[] arg0, Principal[] arg1, Socket arg2) {

		return "default";
	}

	public String[] getServerAliases(String arg0, Principal[] arg1) {

		return null;
	}

	public String chooseServerAlias(String arg0, Principal[] arg1, Socket arg2) {

		return null;
	}

	public X509Certificate[] getCertificateChain(String arg0) {

		return chain;
	}

	public PrivateKey getPrivateKey(String arg0) {

		return key;
	}

}