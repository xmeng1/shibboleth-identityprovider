/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved
 * 
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 * disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided with the distribution, if any, must include the
 * following acknowledgment: "This product includes software developed by the University Corporation for Advanced
 * Internet Development <http://www.ucaid.edu> Internet2 Project. Alternately, this acknowledegement may appear in the
 * software itself, if and wherever such third-party acknowledgments normally appear.
 * 
 * Neither the name of Shibboleth nor the names of its contributors, nor Internet2, nor the University Corporation for
 * Advanced Internet Development, Inc., nor UCAID may be used to endorse or promote products derived from this software
 * without specific prior written permission. For written permission, please contact shibboleth@shibboleth.org
 * 
 * Products derived from this software may not be called Shibboleth, Internet2, UCAID, or the University Corporation
 * for Advanced Internet Development, nor may Shibboleth appear in their name, without prior written permission of the
 * University Corporation for Advanced Internet Development.
 * 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND WITH ALL FAULTS. ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE,
 * ACCURACY, AND EFFORT IS WITH LICENSEE. IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.aa.attrresolv;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;

import org.apache.log4j.Logger;
import org.opensaml.SAMLException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolverAttributeSet.ResolverAttributeIterator;
import edu.internet2.middleware.shibboleth.aa.attrresolv.provider.ValueHandler;
import edu.internet2.middleware.shibboleth.common.ShibResource;
import edu.internet2.middleware.shibboleth.common.ShibResource.ResourceNotAvailableException;
import edu.internet2.middleware.shibboleth.idp.IdPConfig;
import edu.internet2.middleware.shibboleth.xml.Parser;

/**
 * An engine for obtaining attribute values for specified principals. Attributes values are resolved using a directed
 * graph of pluggable attribute definitions and data connectors.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 *  
 */

public class AttributeResolver {

	private static Logger log = Logger.getLogger(AttributeResolver.class.getName());
	private HashMap plugIns = new HashMap();
	private ResolverCache resolverCache = new ResolverCache();
	public static final String resolverNamespace = "urn:mace:shibboleth:resolver:1.0";

	public AttributeResolver(IdPConfig configuration) throws AttributeResolverException {
		
		if (configuration == null || configuration.getResolverConfigLocation() == null) {
			log.error("No Attribute Resolver configuration file specified.");
			throw new AttributeResolverException("No Attribute Resolver configuration file specified.");
		}
		
		loadConfig(configuration.getResolverConfigLocation());
	}
	
	public AttributeResolver(String configFileLocation) throws AttributeResolverException {
		loadConfig(configFileLocation);
	}

	private void loadConfig(String configFile) throws AttributeResolverException {
		try {
			ShibResource config = new ShibResource(configFile, this.getClass());
			Parser.DOMParser parser = new Parser.DOMParser(true);
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
		} catch (SAMLException e) {
			log.error("Error parsing Attribute Resolver Configuration file: " + e);
			throw new AttributeResolverException("Error parsing Attribute Resolver Configuration file.");
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

	private void verifyPlugIns() throws AttributeResolverException {

		log.info("Verifying PlugIn graph consitency.");
		Set inconsistent = new HashSet();
		Iterator registered = plugIns.keySet().iterator();

		while (registered.hasNext()) {
			ResolutionPlugIn plugIn = lookupPlugIn((String) registered.next());
			log.debug("Checking PlugIn (" + plugIn.getId() + ") for consistency.");
			verifyPlugIn(plugIn, new HashSet(), inconsistent);
		}

		if (!inconsistent.isEmpty()) {
			log.info("Unloading inconsistent PlugIns.");
			Iterator inconsistentIt = inconsistent.iterator();
			while (inconsistentIt.hasNext()) {
				plugIns.remove(inconsistentIt.next());
			}
		}

		if (plugIns.size() < 1) {
			log.error("Failed to load any PlugIn definitions.");
			throw new AttributeResolverException("Cannot load Attribute Resolver.");
		}

	}

	private void verifyPlugIn(ResolutionPlugIn plugIn, Set verifyChain, Set inconsistent) {

		//Short-circuit if we have already found this PlugIn to be inconsistent
		if (inconsistent.contains(plugIn.getId())) {
			return;
		}

		//Make sure that we don't have a circular dependency
		if (verifyChain.contains(plugIn.getId())) {
			log.error(
				"The PlugIn (" + plugIn.getId() + ") is inconsistent.  It is involved in a circular dependency chain.");
			inconsistent.add(plugIn.getId());
			return;
		}

		//Recursively go through all DataConnector dependencies and make sure all are registered and consistent.
		List depends = new ArrayList();
		depends.addAll(Arrays.asList(plugIn.getDataConnectorDependencyIds()));
		Iterator dependsIt = depends.iterator();
		while (dependsIt.hasNext()) {
			String key = (String) dependsIt.next();
			if (!plugIns.containsKey(key)) {
				log.error(
					"The PlugIn ("
						+ plugIn.getId()
						+ ") is inconsistent.  It depends on a PlugIn ("
						+ key
						+ ") that is not registered.");
				inconsistent.add(plugIn.getId());
				return;
			}

			ResolutionPlugIn dependent = lookupPlugIn(key);
			if (!(dependent instanceof DataConnectorPlugIn)) {
				log.error(
					"The PlugIn ("
						+ plugIn.getId()
						+ ") is inconsistent.  It depends on a PlugIn ("
						+ key
						+ ") that is mislabeled as an DataConnectorPlugIn.");
				inconsistent.add(plugIn.getId());
				return;
			}

			verifyChain.add(plugIn.getId());
			verifyPlugIn(dependent, verifyChain, inconsistent);

			if (inconsistent.contains(key)) {
				log.error(
					"The PlugIn ("
						+ plugIn.getId()
						+ ") is inconsistent.  It depends on a PlugIn ("
						+ key
						+ ") that is inconsistent.");
				inconsistent.add(plugIn.getId());
				return;
			}
		}
		verifyChain.remove(plugIn.getId());

		//Recursively go through all AttributeDefinition dependencies and make sure all are registered and consistent.
		depends.clear();
		depends.addAll(Arrays.asList(plugIn.getAttributeDefinitionDependencyIds()));
		dependsIt = depends.iterator();
		while (dependsIt.hasNext()) {
			String key = (String) dependsIt.next();

			if (!plugIns.containsKey(key)) {
				log.error(
					"The PlugIn ("
						+ plugIn.getId()
						+ ") is inconsistent.  It depends on a PlugIn ("
						+ key
						+ ") that is not registered.");
				inconsistent.add(plugIn.getId());
				return;
			}

			ResolutionPlugIn dependent = lookupPlugIn(key);
			if (!(dependent instanceof AttributeDefinitionPlugIn)) {
				log.error(
					"The PlugIn ("
						+ plugIn.getId()
						+ ") is inconsistent.  It depends on a PlugIn ("
						+ key
						+ ") that is mislabeled as an AttributeDefinitionPlugIn.");
				inconsistent.add(plugIn.getId());
				return;
			}

			verifyChain.add(plugIn.getId());
			verifyPlugIn(dependent, verifyChain, inconsistent);

			if (inconsistent.contains(key)) {
				log.error(
					"The PlugIn ("
						+ plugIn.getId()
						+ ") is inconsistent.  It depends on a PlugIn ("
						+ key
						+ ") that is inconsistent.");
				inconsistent.add(plugIn.getId());
				return;
			}
		}
		verifyChain.remove(plugIn.getId());

		//Check the failover dependency, if there is one.
		if (plugIn instanceof DataConnectorPlugIn) {
			String key = ((DataConnectorPlugIn) plugIn).getFailoverDependencyId();
			if (key != null) {
				if (!plugIns.containsKey(key)) {
					log.error(
						"The PlugIn ("
							+ plugIn.getId()
							+ ") is inconsistent.  It depends on a PlugIn ("
							+ key
							+ ") that is not registered.");
					inconsistent.add(plugIn.getId());
					return;
				}

				ResolutionPlugIn dependent = lookupPlugIn(key);
				if (!(dependent instanceof DataConnectorPlugIn)) {
					log.error(
						"The PlugIn ("
							+ plugIn.getId()
							+ ") is inconsistent.  It depends on a fail-over PlugIn ("
							+ key
							+ ") that is not a DataConnectorPlugIn.");
					inconsistent.add(plugIn.getId());
					return;
				}

				verifyChain.add(plugIn.getId());
				verifyPlugIn(dependent, verifyChain, inconsistent);

				if (inconsistent.contains(key)) {
					log.error(
						"The PlugIn ("
							+ plugIn.getId()
							+ ") is inconsistent.  It depends on a PlugIn ("
							+ key
							+ ") that is inconsistent.");
					inconsistent.add(plugIn.getId());
					return;
				}
			}
		}
		verifyChain.remove(plugIn.getId());
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

	/**
	 * Resolve a set of attributes for a particular principal and requester.
	 * 
	 * @param principal
	 *            the <code>Principal</code> for which the attributes should be resolved
	 * @param requester
	 *            the name of the requesting entity
	 * @param attributes
	 *            the set of attributes to be resolved
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

	public String[] listRegisteredAttributeDefinitionPlugIns() {

		log.debug("Listing available Attribute Definition PlugIns.");
		Set found = new HashSet();
		Iterator registered = plugIns.keySet().iterator();

		while (registered.hasNext()) {
			ResolutionPlugIn plugIn = lookupPlugIn((String) registered.next());
			if (plugIn instanceof AttributeDefinitionPlugIn) {
				found.add(((AttributeDefinitionPlugIn) plugIn).getId());
			}
		}

		if (log.isDebugEnabled()) {
			for (Iterator iterator = found.iterator(); iterator.hasNext();) {
				log.debug("Found registered Attribute Definition: " + (String) iterator.next());
			}
		}
		return (String[]) found.toArray(new String[0]);
	}

	private Attributes resolveConnector(
		String connector,
		Principal principal,
		String requester,
		Map requestCache,
		ResolverAttributeSet requestedAttributes)
		throws ResolutionPlugInException {

		DataConnectorPlugIn currentDefinition = (DataConnectorPlugIn) lookupPlugIn(connector);

		//Check to see if we have already resolved the connector during this request
		if (requestCache.containsKey(currentDefinition.getId())) {
			log.debug(
				"Connector ("
					+ currentDefinition.getId()
					+ ") already resolved for this request, using cached version");
			return (Attributes) requestCache.get(currentDefinition.getId());
		}

		//Check to see if we have a cached resolution for this connector
		if (currentDefinition.getTTL() > 0) {
			Attributes cachedAttributes = resolverCache.getResolvedConnector(principal, currentDefinition.getId());
			if (cachedAttributes != null) {
				log.debug(
					"Connector ("
						+ currentDefinition.getId()
						+ ") resolution cached from a previous request, using cached version");
				return cachedAttributes;
			}
		}

		//Resolve all attribute dependencies
		String[] attributeDependencies = currentDefinition.getAttributeDefinitionDependencyIds();
		Dependencies depends = new Dependencies();

		for (int i = 0; attributeDependencies.length > i; i++) {
			log.debug(
				"Connector ("
					+ currentDefinition.getId()
					+ ") depends on attribute ("
					+ attributeDependencies[i]
					+ ").");
			ResolverAttribute dependant = requestedAttributes.getByName(attributeDependencies[i]);
			if (dependant == null) {
				dependant = new DependentOnlyResolutionAttribute(attributeDependencies[i]);
			}
			resolveAttribute(dependant, principal, requester, requestCache, requestedAttributes);
			depends.addAttributeResolution(attributeDependencies[i], dependant);

		}

		//Resolve all connector dependencies
		String[] connectorDependencies = currentDefinition.getDataConnectorDependencyIds();
		for (int i = 0; connectorDependencies.length > i; i++) {
			log.debug(
				"Connector ("
					+ currentDefinition.getId()
					+ ") depends on connector ("
					+ connectorDependencies[i]
					+ ").");
			depends.addConnectorResolution(
				connectorDependencies[i],
				resolveConnector(connectorDependencies[i], principal, requester, requestCache, requestedAttributes));
		}

		//Resolve the connector
		Attributes resolvedAttributes = null;
		try {
			resolvedAttributes = currentDefinition.resolve(principal, requester, depends);

			//Add attribute resolution to cache
			if (currentDefinition.getTTL() > 0) {
				resolverCache.cacheConnectorResolution(
					principal,
					currentDefinition.getId(),
					currentDefinition.getTTL(),
					resolvedAttributes);
			}
		} catch (ResolutionPlugInException e) {
			// Something went wrong, so check for a fail-over...
			if (currentDefinition.getFailoverDependencyId() != null) {
				log.warn("Connector (" + currentDefinition.getId() + ") failed, invoking failover dependency");
				resolvedAttributes =
					resolveConnector(
						currentDefinition.getFailoverDependencyId(),
						principal,
						requester,
						requestCache,
						requestedAttributes);
			} else if (currentDefinition.getPropagateErrors()) {
				throw e;
			} else {
				log.warn(
					"Connector ("
						+ currentDefinition.getId()
						+ ") returning empty attribute set instead of propagating error: "
						+ e);
				resolvedAttributes = new BasicAttributes();
			}
		}

		//Cache for this request
		requestCache.put(currentDefinition.getId(), resolvedAttributes);
		return resolvedAttributes;
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
		// (this checks dependency-only attributes and attributes resolved with no values
		if (requestCache.containsKey(currentDefinition.getId())) {
			log.debug(
				"Attribute ("
					+ currentDefinition.getId()
					+ ") already resolved for this request, using cached version");
			attribute.resolveFromCached((ResolverAttribute) requestCache.get(currentDefinition.getId()));
			return;
		}

		//Check to see if we have already resolved the attribute during this request
		// (this checks attributes that were submitted to the AR for resolution)
		ResolverAttribute requestedAttribute = requestedAttributes.getByName(currentDefinition.getId());
		if (requestedAttribute != null) {
			if (requestedAttribute.resolved()) {
				attribute.resolveFromCached(requestedAttribute);
			}
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
		Dependencies depends = new Dependencies();
		String[] attributeDependencies = currentDefinition.getAttributeDefinitionDependencyIds();

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
			depends.addConnectorResolution(
				connectorDependencies[i],
				resolveConnector(connectorDependencies[i], principal, requester, requestCache, requestedAttributes));
		}

		//Resolve the attribute
		try {
			currentDefinition.resolve(attribute, principal, requester, depends);

			//Add attribute resolution to cache
			if (currentDefinition.getTTL() > 0) {
				resolverCache.cacheAttributeResolution(
					principal,
					attribute.getName(),
					currentDefinition.getTTL(),
					attribute);
			}
		} catch (ResolutionPlugInException e) {
			if (currentDefinition.getPropagateErrors()) {
				throw e;
			} else {
				log.warn(
					"Attribute ("
						+ currentDefinition.getId()
						+ ") returning no values instead of propagating error: "
						+ e);
			}
		}

		//If necessary, cache for this request
		if (dependancyOnly || !attribute.hasValues()) {
			requestCache.put(currentDefinition.getId(), attribute);
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

	/**
	 * Cleanup resources that won't be released when this object is garbage-collected
	 */
	public void destroy() {
		resolverCache.destroy();
	}
}
