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

package edu.internet2.middleware.shibboleth.aa.arp;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

import edu.internet2.middleware.shibboleth.idp.IdPConfig;
import edu.internet2.middleware.shibboleth.xml.Parser;

/**
 * Defines a processing engine for Attribute Release Policies.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */

public class ArpEngine {

	private static Logger log = Logger.getLogger(ArpEngine.class.getName());
	private ArpRepository repository;
	private static Map<URI, String> matchFunctions = Collections.synchronizedMap(new HashMap<URI, String>());
	static {
		// Initialize built-in match functions
		try {

			// Current
			matchFunctions.put(new URI("urn:mace:shibboleth:arp:matchFunction:regexMatch"),
					"edu.internet2.middleware.shibboleth.aa.arp.provider.RegexMatchFunction");
			matchFunctions.put(new URI("urn:mace:shibboleth:arp:matchFunction:regexNotMatch"),
					"edu.internet2.middleware.shibboleth.aa.arp.provider.RegexNotMatchFunction");
			matchFunctions.put(new URI("urn:mace:shibboleth:arp:matchFunction:stringMatch"),
					"edu.internet2.middleware.shibboleth.aa.arp.provider.StringValueMatchFunction");
			matchFunctions.put(new URI("urn:mace:shibboleth:arp:matchFunction:stringNotMatch"),
					"edu.internet2.middleware.shibboleth.aa.arp.provider.StringValueNotMatchFunction");

			// Legacy
			matchFunctions.put(new URI("urn:mace:shibboleth:arp:matchFunction:exactShar"),
					"edu.internet2.middleware.shibboleth.aa.arp.provider.StringValueMatchFunction");
			matchFunctions.put(new URI("urn:mace:shibboleth:arp:matchFunction:resourceTree"),
					"edu.internet2.middleware.shibboleth.aa.arp.provider.ResourceTreeMatchFunction");
			matchFunctions.put(new URI("urn:mace:shibboleth:arp:matchFunction:stringValue"),
					"edu.internet2.middleware.shibboleth.aa.arp.provider.StringValueMatchFunction");

		} catch (URISyntaxException e) {
			log.error("Error mapping standard match functions: " + e);
		}
	}

	/**
	 * Loads Arp Engine with default configuration
	 * 
	 * @throws ArpException
	 *             if engine cannot be loaded
	 */
	public ArpEngine(Element config) throws ArpException {

		if (!config.getLocalName().equals("ReleasePolicyEngine")) { throw new IllegalArgumentException(); }

		NodeList itemElements = config.getElementsByTagNameNS(IdPConfig.configNameSpace, "ArpRepository");

		if (itemElements.getLength() > 1) {
			log
					.warn("Encountered multiple <ArpRepository> configuration elements.  Arp Engine currently only supports one.  Using first...");
		}

		if (itemElements.getLength() == 0) {
			log.error("No <ArpRepsitory/> specified for this Arp Endine.");
			throw new ArpException("Could not start Arp Engine.");
		}

		try {
			repository = ArpRepositoryFactory.getInstance((Element) itemElements.item(0));
		} catch (ArpRepositoryException e) {
			log.error("Could not start Arp Engine: " + e);
			throw new ArpException("Could not start Arp Engine.");
		}
	}

	public ArpEngine(ArpRepository preLoadedRepository) throws ArpException {

		repository = preLoadedRepository;
	}

	/**
	 * Loads Arp Engine based on XML configurationf
	 * 
	 * @throws ArpException
	 *             if configuration is invalid or there is a problem loading the engine
	 */
	public ArpEngine() throws ArpException {

		DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
		docFactory.setNamespaceAware(true);
		Document placeHolder;
		try {
			placeHolder = docFactory.newDocumentBuilder().newDocument();

			Element defRepository = placeHolder.createElementNS(IdPConfig.configNameSpace, "ArpRepository");
			defRepository.setAttributeNS(IdPConfig.configNameSpace, "implementation",
					"edu.internet2.middleware.shibboleth.aa.arp.provider.FileSystemArpRepository");

			Element path = placeHolder.createElementNS(IdPConfig.configNameSpace, "Path");
			Text text = placeHolder.createTextNode("/conf/arps/");
			path.appendChild(text);

			defRepository.appendChild(path);

			repository = ArpRepositoryFactory.getInstance(defRepository);

		} catch (ArpRepositoryException e) {
			log.error("Could not start Arp Engine: " + e);
			throw new ArpException("Could not start Arp Engine.");
		} catch (ParserConfigurationException e) {
			log.error("Problem loading parser to create default Arp Engine configuration: " + e);
			throw new ArpException("Could not start Arp Engine.");
		}
	}

	public static MatchFunction lookupMatchFunction(URI functionIdentifier) throws ArpException {

		String className = null;

		synchronized (matchFunctions) {
			className = (String) matchFunctions.get(functionIdentifier);
		}

		if (className == null) { return null; }
		try {
			Class matchFunction = Class.forName(className);
			Object functionObject = matchFunction.newInstance();
			if (functionObject instanceof MatchFunction) {
				return (MatchFunction) functionObject;
			} else {
				log.error("Improperly specified match function, (" + className + ") is not a match function.");
				throw new ArpException("Improperly specified match function, (" + className
						+ ") is not a match function.");
			}
		} catch (Exception e) {
			log.error("Could not load Match Function: (" + className + "): " + e);
			throw new ArpException("Could not load Match Function.");
		}
	}

	private Arp createEffectiveArp(Principal principal, String requester, URL resource) throws ArpProcessingException {

		try {
			Arp effectiveArp = new Arp(principal);
			effectiveArp.setDescription("Effective ARP.");

			Arp[] userPolicies = repository.getAllPolicies(principal);

			if (log.isDebugEnabled()) {
				log.debug("Creating effective ARP from (" + userPolicies.length + ") polic(y|ies).");
				try {
					for (int i = 0; userPolicies.length > i; i++) {
						String dump = Parser.serialize(userPolicies[i].unmarshall());
						log.debug("Dumping ARP:" + System.getProperty("line.separator") + dump);
					}
				} catch (Exception e) {
					log
							.error("Encountered a strange error while writing ARP debug messages.  This should never happen.");
				}
			}

			for (int i = 0; userPolicies.length > i; i++) {
				Rule[] rules = userPolicies[i].getMatchingRules(requester, resource);

				for (int j = 0; rules.length > j; j++) {
					effectiveArp.addRule(rules[j]);
				}
			}
			return effectiveArp;

		} catch (ArpRepositoryException e) {
			log.error("Error creating effective policy: " + e);
			throw new ArpProcessingException("Error creating effective policy.");
		}
	}

	/**
	 * Determines which attributes MIGHT be releasable for a given request. This function may be used to determine which
	 * attributes to resolve when a request for all attributes is made. This is done for performance reasons only. ie:
	 * The resulting attributes must still be filtered before release.
	 * 
	 * @return an array of <code>URI</code> objects that name the possible attributes
	 */
	public Set<URI> listPossibleReleaseAttributes(Principal principal, String requester, URL resource)
			throws ArpProcessingException {

		Set<URI> possibleReleaseSet = new HashSet<URI>();
		Set<URI> anyValueDenies = new HashSet<URI>();
		Rule[] rules = createEffectiveArp(principal, requester, resource).getAllRules();
		for (int i = 0; rules.length > i; i++) {
			Rule.Attribute[] attributes = rules[i].getAttributes();
			for (int j = 0; attributes.length > j; j++) {
				if (attributes[j].releaseAnyValue()) {
					possibleReleaseSet.add(attributes[j].getName());
				} else if (attributes[j].denyAnyValue()) {
					anyValueDenies.add(attributes[j].getName());
				} else {
					Rule.AttributeValue[] values = attributes[j].getValues();
					for (int k = 0; values.length > k; k++) {
						if (values[k].getRelease().equals("permit")) {
							possibleReleaseSet.add(attributes[j].getName());
							break;
						}
					}
				}
			}
		}
		possibleReleaseSet.removeAll(anyValueDenies);
		if (log.isDebugEnabled()) {
			log.debug("Computed possible attribute release set.");
			Iterator iterator = possibleReleaseSet.iterator();
			while (iterator.hasNext()) {
				log.debug("Possible attribute: " + iterator.next().toString());
			}
		}
		return possibleReleaseSet;
	}

	/**
	 * Applies all applicable ARPs to a set of attributes.
	 * 
	 * @return the attributes to be released
	 */
	public void filterAttributes(Collection<ArpAttribute> attributes, Principal principal, String requester,
			URL resource) throws ArpProcessingException {

		if (attributes.isEmpty()) {
			log.debug("ARP Engine was asked to apply filter to empty attribute set.");
			return;
		}

		log.info("Applying Attribute Release Policies.");
		if (log.isDebugEnabled()) {
			log.debug("Processing the following attributes:");
			for (Iterator<ArpAttribute> attrIterator = attributes.iterator(); attrIterator.hasNext();) {
				log.debug("Attribute: (" + attrIterator.next().getName() + ")");
			}
		}

		// Gather all applicable ARP attribute specifiers
		Set<String> attributeNames = new HashSet<String>();
		for (Iterator<ArpAttribute> nameIterator = attributes.iterator(); nameIterator.hasNext();) {
			attributeNames.add(nameIterator.next().getName());
		}
		Rule[] rules = createEffectiveArp(principal, requester, resource).getAllRules();
		Set<Rule.Attribute> applicableRuleAttributes = new HashSet<Rule.Attribute>();
		for (int i = 0; rules.length > i; i++) {
			Rule.Attribute[] ruleAttributes = rules[i].getAttributes();
			for (int j = 0; ruleAttributes.length > j; j++) {
				if (attributeNames.contains(ruleAttributes[j].getName().toString())) {
					applicableRuleAttributes.add(ruleAttributes[j]);
				}
			}
		}

		// Canonicalize specifiers
		Map arpAttributeSpecs = createCanonicalAttributeSpec((Rule.Attribute[]) applicableRuleAttributes
				.toArray(new Rule.Attribute[0]));

		// Filter
		for (Iterator<ArpAttribute> returnIterator = attributes.iterator(); returnIterator.hasNext();) {

			ArpAttribute arpAttribute = returnIterator.next();
			Rule.Attribute attribute = (Rule.Attribute) arpAttributeSpecs.get(arpAttribute.getName());

			// Handle no specifier
			if (attribute == null) {
				returnIterator.remove();
				continue;
			}

			// Handle Deny All
			if (attribute.denyAnyValue()) {
				returnIterator.remove();
				continue;
			}

			// Handle Permit All
			if (attribute.releaseAnyValue() && attribute.getValues().length == 0) {
				continue;
			}

			// Handle "Permit All-Except" and "Permit Specific"
			ArrayList releaseValues = new ArrayList();
			for (Iterator valueIterator = arpAttribute.getValues(); valueIterator.hasNext();) {
				Object value = valueIterator.next();
				if (attribute.isValuePermitted(value)) {
					releaseValues.add(value);
				}
			}

			if (!releaseValues.isEmpty()) {
				arpAttribute.setValues((Object[]) releaseValues.toArray(new Object[0]));
			} else {
				returnIterator.remove();
			}

		}
	}

	private Map<String, Rule.Attribute> createCanonicalAttributeSpec(Rule.Attribute[] attributes) {

		Map<String, Rule.Attribute> canonicalSpec = new HashMap<String, Rule.Attribute>();
		for (int i = 0; attributes.length > i; i++) {
			if (!canonicalSpec.containsKey(attributes[i].getName().toString())) {
				canonicalSpec.put(attributes[i].getName().toString(), attributes[i]);
			} else {
				if (((Rule.Attribute) canonicalSpec.get(attributes[i].getName().toString())).denyAnyValue()) {
					continue;
				}
				if (attributes[i].denyAnyValue()) {
					((Rule.Attribute) canonicalSpec.get(attributes[i].getName().toString())).setAnyValueDeny(true);
					continue;
				}
				if (attributes[i].releaseAnyValue()) {
					((Rule.Attribute) canonicalSpec.get(attributes[i].getName().toString())).setAnyValuePermit(true);
				}
				Rule.AttributeValue[] values = attributes[i].getValues();
				for (int j = 0; values.length > j; j++) {
					((Rule.Attribute) canonicalSpec.get(attributes[i].getName().toString())).addValue(values[j]);
				}
			}
		}
		return canonicalSpec;
	}

	/**
	 * Cleanup resources that won't be released when this object is garbage-collected
	 */
	public void destroy() {

		repository.destroy();
	}

}
