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

package edu.internet2.middleware.shibboleth.aa.attrresolv;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import javax.naming.directory.Attributes;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.xerces.parsers.DOMParser;
import org.apache.xml.serialize.OutputFormat;
import org.apache.xml.serialize.XMLSerializer;
import org.opensaml.SAMLException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.EntityResolver;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import sun.security.acl.PrincipalImpl;
import edu.internet2.middleware.shibboleth.aa.AAAttribute;
import edu.internet2.middleware.shibboleth.aa.AAAttributeSet;
import edu.internet2.middleware.shibboleth.aa.AAAttributeSet.ShibAttributeIterator;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolverAttributeSet.ResolverAttributeIterator;
import edu.internet2.middleware.shibboleth.aa.attrresolv.provider.ValueHandler;
import edu.internet2.middleware.shibboleth.common.ShibResource;
import edu.internet2.middleware.shibboleth.common.ShibResource.ResourceNotAvailableException;

/**
 * An engine for obtaining attribute values for specified principals.  Attributes values are
 * resolved using a directed graph of pluggable attribute definitions and data connectors.
 *   
 * @author Walter Hoehn (wassa@columbia.edu)
 *
 */

public class AttributeResolver {

	private static Logger log = Logger.getLogger(AttributeResolver.class.getName());
	private HashMap plugIns = new HashMap();
	private ResolverCache resolverCache = new ResolverCache();
	public static final String resolverNamespace = "urn:mace:shibboleth:resolver:1.0";

	public AttributeResolver(Properties properties) throws AttributeResolverException {
		if (properties
			.getProperty("edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver.ResolverConfig")
			== null) {
			log.error("No Attribute Resolver configuration file specified.");
			throw new AttributeResolverException("No Attribute Resolver configuration file specified.");
		}

		String configFile =
			properties.getProperty(
				"edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver.ResolverConfig");

		try {
			ShibResource config = new ShibResource(configFile, this.getClass());
			DOMParser parser = new DOMParser();
			parser.setFeature("http://xml.org/sax/features/validation", true);
			parser.setFeature("http://apache.org/xml/features/validation/schema", true);
			parser.setEntityResolver(new EntityResolver() {
				public InputSource resolveEntity(String publicId, String systemId) throws SAXException {
					if (systemId.endsWith("shibboleth-resolver-1.0.xsd")) {
						InputStream stream;
						try {
							return new InputSource(
								new ShibResource("/schemas/shibboleth-resolver-1.0.xsd",
									this.getClass())
									.getInputStream());
						} catch (IOException e) {
							throw new SAXException("Could not load entity: " + e);
						}
					} else {
						return null;
					}
				}
			});

			parser.setErrorHandler(new ErrorHandler() {
				public void error(SAXParseException arg0) throws SAXException {
					throw new SAXException("Error parsing xml file: " + arg0);
				}
				public void fatalError(SAXParseException arg0) throws SAXException {
					throw new SAXException("Error parsing xml file: " + arg0);
				}
				public void warning(SAXParseException arg0) throws SAXException {
					throw new SAXException("Error parsing xml file: " + arg0);
				}
			});
			parser.parse(new InputSource(config.getInputStream()));
			loadConfig(parser.getDocument());

		} catch (ResourceNotAvailableException e) {
			log.error("No Attribute Resolver configuration could be loaded from (" + configFile + "): " + e);
			throw new AttributeResolverException("No Attribute Resolver configuration found.");
		} catch (SAXException e) {
			log.error("Error parsing Attribute Resolver Configuration file: " + e);
			throw new AttributeResolverException("Error parsing Attribute Resolver Configuration file.");
		} catch (IOException e) {
			log.error("Error reading Attribute Resolver Configuration file: " + e);
			throw new AttributeResolverException("Error reading Attribute Resolver Configuration file.");
		}
	}

	private void loadConfig(Document document) throws AttributeResolverException {

		log.info("Configuring Attribute Resolver.");
		if (!document.getDocumentElement().getTagName().equals("AttributeResolver")) {
			log.error("Configuration must include <AttributeResolver> as the root node.");
			throw new AttributeResolverException("Cannot load Attribute Resolver.");
		}

		NodeList plugInNodes =
			document.getElementsByTagNameNS(resolverNamespace, "AttributeResolver").item(0).getChildNodes();
		if (plugInNodes.getLength() <= 0) {
			log.error("Configuration inclues no PlugIn definitions.");
			throw new AttributeResolverException("Cannot load Attribute Resolver.");
		}
		for (int i = 0; plugInNodes.getLength() > i; i++) {
			if (plugInNodes.item(i).getNodeType() == Node.ELEMENT_NODE) {
				try {
					log.info("Found a PlugIn. Loading...");
					ResolutionPlugIn plugIn = ResolutionPlugInFactory.createPlugIn((Element) plugInNodes.item(i));
					registerPlugIn(plugIn, plugIn.getId());
				} catch (DuplicatePlugInException dpe) {
					log.warn("Skipping PlugIn: " + dpe.getMessage());
				} catch (ClassCastException cce) {
					log.error("Problem realizing PlugIn configuration" + cce.getMessage());
				} catch (AttributeResolverException are) {
					log.warn("Skipping PlugIn: " + ((Element) plugInNodes.item(i)).getAttribute("id"));
				}
			}
		}

		verifyPlugIns();
		log.info("Configuration complete.");
	}

	private void verifyPlugIns() {
		//TODO Maybe this should detect loops in the directed graph

		log.info("Verifying PlugIn graph consitency.");
		Set inconsistent = new HashSet();
		Iterator registered = plugIns.keySet().iterator();

		while (registered.hasNext()) {
			ResolutionPlugIn plugIn = lookupPlugIn((String) registered.next());
			if (plugIn instanceof AttributeDefinitionPlugIn) {
				log.debug("Checking PlugIn (" + plugIn.getId() + ") for consistency.");
				List depends = new ArrayList();
				depends.addAll(
					Arrays.asList(((AttributeDefinitionPlugIn) plugIn).getAttributeDefinitionDependencyIds()));
				depends.addAll(Arrays.asList(((AttributeDefinitionPlugIn) plugIn).getDataConnectorDependencyIds()));
				Iterator dependsIt = depends.iterator();
				while (dependsIt.hasNext()) {
					if (!plugIns.containsKey(dependsIt.next())) {
						log.error(
							"The PlugIn ("
								+ plugIn.getId()
								+ ") is inconsistent.  It depends on a PlugIn that is not registered.");
						inconsistent.add(plugIn.getId());
					}
				}
			}
		}

		if (!inconsistent.isEmpty()) {
			log.info("Unloading inconsistent PlugIns.");
			Iterator inconsistentIt = inconsistent.iterator();
			while (inconsistentIt.hasNext()) {
				plugIns.remove(inconsistentIt.next());
			}
		}
	}

	private void registerPlugIn(ResolutionPlugIn connector, String id) throws DuplicatePlugInException {

		if (plugIns.containsKey(id)) {
			log.error("A PlugIn is already registered with the Id (" + id + ").");
			throw new DuplicatePlugInException("Found a duplicate PlugIn Id.");
		}
		plugIns.put(id, connector);
		log.info("Registered PlugIn: (" + id + ")");

	}

	private ResolutionPlugIn lookupPlugIn(String id) {
		return (ResolutionPlugIn) plugIns.get(id);
	}

	public static void main(String[] args) {

		BasicConfigurator.configure();
		Logger.getRootLogger().setLevel(Level.WARN);

		try {
			Properties props = new Properties();
			File file = new File("src/conf/resolver.xml");

			props.setProperty(
				"edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver.ResolverConfig",
				file.toURL().toString());
			AttributeResolver ar = new AttributeResolver(props);
			for (int j = 0; j < 2; j++) {
				System.out.println("Resolving pass: " + (j + 1));
				AAAttributeSet attributes = new AAAttributeSet();
				if (j == 1) {
					attributes.add(new AAAttribute("urn:mace:eduPerson:1.0:eduPersonPrincipalName"));
				}
				attributes.add(new AAAttribute("urn:mace:eduPerson:1.0:eduPersonNickName"));
				attributes.add(new AAAttribute("urn:mace:eduPerson:1.0:eduPersonPrimaryAffiliation"));
				attributes.add(new AAAttribute("urn:mace:eduPerson:1.0:eduPersonScopedAffiliation"));
				attributes.add(new AAAttribute("urn:mace:eduPerson:1.0:eduPersonAffiliation"));
				attributes.add(new AAAttribute("urn:mace:eduPerson:1.0:eduPersonEntitlement"));
				attributes.add(new AAAttribute("urn:mace:rfc2079:labeledURI"));

				ar.resolveAttributes(new PrincipalImpl("mytestuser"), "shar.example.edu", attributes);
				ShibAttributeIterator iterator = attributes.shibAttributeIterator();
				while (iterator.hasNext()) {
					AAAttribute attribute = iterator.nextShibAttribute();
					System.out.println(attribute.getName());
					System.out.println("LifeTime: " + attribute.getLifetime());
					System.out.println("\t" + " values:");
					for (Iterator attrIterator = attribute.getValues(); attrIterator.hasNext();) {
						System.out.println("\t\t" + attrIterator.next().toString());
					}
					System.out.println("To DOM:");
					Node dom = attribute.toDOM();
					ByteArrayOutputStream xmlOut = new ByteArrayOutputStream();
					new XMLSerializer(xmlOut, new OutputFormat()).serialize((Element) dom);
					System.out.write(xmlOut.toByteArray());
					System.out.println(System.getProperty("line.separator") + System.getProperty("line.separator"));
				}
			}

		} catch (AttributeResolverException e) {
			log.error("Couldn't load attribute resolver: " + e.getMessage());
		} catch (MalformedURLException e1) {
			e1.printStackTrace();
		} catch (SAMLException se) {
			se.printStackTrace();
		} catch (IOException e) {
			log.error("Couldn't load attribute resolver: " + e.getMessage());
		}
	}

	/**
	 * Resolve a set of attributes for a particular principal and requester.
	 * 
	 * @param principal the <code>Principal</code> for which the attributes should be resolved
	 * @param requester the name of the requesting entity
	 * @param attributes the set of attributes to be resolved
	 */
	public void resolveAttributes(Principal principal, String requester, ResolverAttributeSet attributes) {

		HashMap requestCache = new HashMap();
		ResolverAttributeIterator iterator = attributes.resolverAttributeIterator();

		while (iterator.hasNext()) {
			ResolverAttribute attribute = iterator.nextResolverAttribute();
			try {
				if (lookupPlugIn(attribute.getName()) == null) {
					log.warn("No PlugIn registered for attribute: (" + attribute.getName() + ")");
					iterator.remove();
				} else {
					log.info("Resolving attribute: (" + attribute.getName() + ")");
					if (attribute.resolved()) {
						log.debug(
							"Attribute ("
								+ attribute.getName()
								+ ") already resolved for this request.  No need for further resolution.");

					} else {
						resolveAttribute(attribute, principal, requester, requestCache, attributes);
					}

					if (!attribute.hasValues()) {
						iterator.remove();
					}
				}
			} catch (ResolutionPlugInException rpe) {
				log.error("Problem encountered while resolving attribute: (" + attribute.getName() + "): " + rpe);
				iterator.remove();
			}
		}
	}

	private void resolveAttribute(
		ResolverAttribute attribute,
		Principal principal,
		String requester,
		Map requestCache,
		ResolverAttributeSet requestedAttributes)
		throws ResolutionPlugInException {

		AttributeDefinitionPlugIn currentDefinition = (AttributeDefinitionPlugIn) lookupPlugIn(attribute.getName());

		//Check to see if we have already resolved the attribute during this request
		if (requestCache.containsKey(currentDefinition.getId())) {
			log.debug(
				"Attribute ("
					+ currentDefinition.getId()
					+ ") already resolved for this request, using cached version");
			attribute.resolveFromCached((ResolverAttribute) requestCache.get(currentDefinition.getId()));
			return;
		}

		//Check to see if we have a cached resolution for this attribute
		if (currentDefinition.getTTL() > 0) {
			ResolverAttribute cachedAttribute =
				resolverCache.getResolvedAttribute(principal, currentDefinition.getId());
			if (cachedAttribute != null) {
				log.debug(
					"Attribute ("
						+ currentDefinition.getId()
						+ ") resolution cached from a previous request, using cached version");
				attribute.resolveFromCached(cachedAttribute);
				return;
			}
		}

		//Resolve all attribute dependencies
		String[] attributeDependencies = currentDefinition.getAttributeDefinitionDependencyIds();
		Dependencies depends = new Dependencies();

		boolean dependancyOnly = false;
		for (int i = 0; attributeDependencies.length > i; i++) {
			log.debug(
				"Attribute (" + attribute.getName() + ") depends on attribute (" + attributeDependencies[i] + ").");
			ResolverAttribute dependant = requestedAttributes.getByName(attributeDependencies[i]);
			if (dependant == null) {
				dependancyOnly = true;
				dependant = new DependentOnlyResolutionAttribute(attributeDependencies[i]);
			}
			resolveAttribute(dependant, principal, requester, requestCache, requestedAttributes);
			depends.addAttributeResolution(attributeDependencies[i], dependant);

		}

		//Resolve all connector dependencies
		String[] connectorDependencies = currentDefinition.getDataConnectorDependencyIds();
		for (int i = 0; connectorDependencies.length > i; i++) {
			log.debug(
				"Attribute (" + attribute.getName() + ") depends on connector (" + connectorDependencies[i] + ").");
			//Check to see if we have already resolved the connector during this request
			if (requestCache.containsKey(connectorDependencies[i])) {
				log.debug(
					"Connector ("
						+ connectorDependencies[i]
						+ ") already resolved for this request, using cached version");
				depends.addConnectorResolution(
					connectorDependencies[i],
					(Attributes) requestCache.get(connectorDependencies[i]));
			} else {
				//Check to see if we have a cached resolution for this attribute
				if (((DataConnectorPlugIn) lookupPlugIn(connectorDependencies[i])).getTTL() > 0) {
					Attributes cachedAttributes =
						resolverCache.getResolvedConnector(principal, connectorDependencies[i]);
					if (cachedAttributes != null) {
						log.debug(
							"Connector ("
								+ connectorDependencies[i]
								+ ") resolution cached from a previous request, using cached version");
						depends.addConnectorResolution(connectorDependencies[i], cachedAttributes);
					}
				}

				Attributes resolvedConnector =
					((DataConnectorPlugIn) lookupPlugIn(connectorDependencies[i])).resolve(principal);
				requestCache.put(connectorDependencies[i], resolvedConnector);
				depends.addConnectorResolution(connectorDependencies[i], resolvedConnector);

				//Add attribute resolution to cache
				if (((DataConnectorPlugIn) lookupPlugIn(connectorDependencies[i])).getTTL() > 0) {
					resolverCache.cacheConnectorResolution(
						principal,
						connectorDependencies[i],
						((DataConnectorPlugIn) lookupPlugIn(connectorDependencies[i])).getTTL(),
						resolvedConnector);
				}
			}
		}

		//Resolve the attribute
		currentDefinition.resolve(attribute, principal, requester, depends);

		//If necessary, cache for this request
		if (dependancyOnly || !attribute.hasValues()) {
			requestCache.put(currentDefinition.getId(), attribute);
		}

		//Add attribute resolution to cache
		if (currentDefinition.getTTL() > 0) {
			resolverCache.cacheAttributeResolution(
				principal,
				attribute.getName(),
				currentDefinition.getTTL(),
				attribute);
		}
	}

	private class DuplicatePlugInException extends Exception {
		public DuplicatePlugInException(String message) {
			super(message);
		}
	}
	
	class DependentOnlyResolutionAttribute implements ResolverAttribute {
		String name;
		ArrayList values = new ArrayList();
		boolean resolved = false;

		DependentOnlyResolutionAttribute(String name) {
			this.name = name;
		}

		public String getName() {
			return name;
		}

		public boolean resolved() {
			return resolved;
		}

		public void setResolved() {
			resolved = true;
		}

		public void resolveFromCached(ResolverAttribute attribute) {
		}

		public void setLifetime(long lifetime) {
		}

		public long getLifetime() {
			return 0;
		}

		public void addValue(Object value) {
			values.add(value);
		}

		public Iterator getValues() {
			return values.iterator();
		}

		public boolean hasValues() {
			if (values.isEmpty()) {
				return false;
			}
			return true;
		}

		public void registerValueHandler(ValueHandler handler) {
		}

		public ValueHandler getRegisteredValueHandler() {
			return null;
		}
	}

}
