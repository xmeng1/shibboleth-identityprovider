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

package edu.internet2.middleware.shibboleth.aa.arp;

import java.io.StringWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.apache.log4j.Logger;
import org.apache.xml.serialize.OutputFormat;
import org.apache.xml.serialize.XMLSerializer;

import edu.internet2.middleware.shibboleth.aa.arp.ArpAttributeSet.ArpAttributeIterator;

/**
 *  Defines a processing engine for Attribute Release Policies.
 *
 * @author Walter Hoehn (wassa@columbia.edu)
 */

public class ArpEngine {

	private static Logger log = Logger.getLogger(ArpEngine.class.getName());
	private ArpRepository repository;
	private static Map matchFunctions = Collections.synchronizedMap(new HashMap());
	static {
		//Initialize built-in match functions
		try {
			matchFunctions.put(
				new URI("urn:mace:shibboleth:arp:matchFunction:exactShar"),
				"edu.internet2.middleware.shibboleth.aa.arp.provider.ExactSharMatchFunction");
			matchFunctions.put(
				new URI("urn:mace:shibboleth:arp:matchFunction:resourceTree"),
				"edu.internet2.middleware.shibboleth.aa.arp.provider.ResourceTreeMatchFunction");
			matchFunctions.put(
				new URI("urn:mace:shibboleth:arp:matchFunction:regexMatch"),
				"edu.internet2.middleware.shibboleth.aa.arp.provider.RegexMatchFunction");
			matchFunctions.put(
				new URI("urn:mace:shibboleth:arp:matchFunction:stringValue"),
				"edu.internet2.middleware.shibboleth.aa.arp.provider.StringValueMatchFunction");
		} catch (URISyntaxException e) {
			log.error("Error mapping standard match functions: " + e);
		}
	}

	public ArpEngine(Properties properties) throws ArpException {
		try {
			repository = ArpRepositoryFactory.getInstance(properties);
		} catch (ArpRepositoryException e) {
			log.error("Could not start Arp Engine: " + e);
			throw new ArpException("Could not start Arp Engine.");
		}
	}

	public ArpEngine(ArpRepository repository, Properties properties) throws ArpException {
		this.repository = repository;
	}

	/**
	 * Lookup by identifier a function for matching ARP Target Components .
	 * @param functionIdentifier the identifier for the function
	 * @return the <code>Matchfunction</code> or null if not registered
	 */

	public static MatchFunction lookupMatchFunction(URI functionIdentifier) throws ArpException {
		String className = null;

		synchronized (matchFunctions) {
			className = (String) matchFunctions.get(functionIdentifier);
		}

		if (className == null) {
			return null;
		}
		try {
			Class matchFunction = Class.forName(className);
			Object functionObject = matchFunction.newInstance();
			if (functionObject instanceof MatchFunction) {
				return (MatchFunction) functionObject;
			} else {
				log.error(
					"Improperly specified match function, (" + className + ") is not a match function.");
				throw new ArpException(
					"Improperly specified match function, (" + className + ") is not a match function.");
			}
		} catch (Exception e) {
			log.error("Could not load Match Function: (" + className + "): " + e);
			throw new ArpException("Could not load Match Function.");
		}
	}

	private Arp createEffectiveArp(Principal principal, String requester, URL resource)
		throws ArpProcessingException {
		try {
			Arp effectiveArp = new Arp(principal);
			effectiveArp.setDescription("Effective ARP.");

			Arp[] userPolicies = repository.getAllPolicies(principal);

			if (log.isDebugEnabled()) {
				log.debug("Creating effective ARP from (" + userPolicies.length + ") polic(y|ies).");
				try {
					for (int i = 0; userPolicies.length > i; i++) {
						StringWriter writer = new StringWriter();
						OutputFormat format = new OutputFormat();
						format.setIndent(4);
						XMLSerializer serializer = new XMLSerializer(writer, format);
						serializer.serialize(userPolicies[i].unmarshall());
						log.debug("Dumping ARP:" + System.getProperty("line.separator") + writer.toString());
					}
				} catch (Exception e) {
					log.error(
						"Encountered a strange error while writing ARP debug messages.  This should never happen.");
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
	 * Determines which attributes MIGHT be releasable for a given request.  This function 
	 * may be used to determine which attributes to resolve when a request for all
	 * attributes is made.  This is done for performance reasons only. ie: The resulting 
	 * attributes must still be filtered before release.
	 * @return an array of <code>URI</code> objects that name the possible attributes
	 */
	public URI[] listPossibleReleaseAttributes(Principal principal, String requester, URL resource)
		throws ArpProcessingException {
		Set possibleReleaseSet = new HashSet();
		Set anyValueDenies = new HashSet();
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
		return (URI[]) possibleReleaseSet.toArray(new URI[0]);
	}

	/**
	 * Applies all applicable ARPs to a set of attributes.
	 * @return the attributes to be released
	 */
	public void filterAttributes(ArpAttributeSet attributes, Principal principal, String requester, URL resource)
		throws ArpProcessingException {

		ArpAttributeIterator iterator = attributes.arpAttributeIterator();
		if (!iterator.hasNext()) {
			log.debug("ARP Engine was asked to apply filter to empty attribute set.");
			return;
		}

		log.info("Applying Attribute Release Policies.");
		if (log.isDebugEnabled()) {
			log.debug("Processing the following attributes:");
			for (ArpAttributeIterator attrIterator = attributes.arpAttributeIterator(); attrIterator.hasNext();) {
				log.debug("Attribute: (" + attrIterator.nextArpAttribute().getName() + ")");
			}
		}

		//Gather all applicable ARP attribute specifiers
		Set attributeNames = new HashSet();
		for (ArpAttributeIterator nameIterator = attributes.arpAttributeIterator(); nameIterator.hasNext();) {
			attributeNames.add(nameIterator.nextArpAttribute().getName());
		}
		Rule[] rules = createEffectiveArp(principal, requester, resource).getAllRules();
		Set applicableRuleAttributes = new HashSet();
		for (int i = 0; rules.length > i; i++) {
			Rule.Attribute[] ruleAttributes = rules[i].getAttributes();
			for (int j = 0; ruleAttributes.length > j; j++) {
				if (attributeNames.contains(ruleAttributes[j].getName().toString())) {
					applicableRuleAttributes.add(ruleAttributes[j]);
				}
			}
		}

		//Canonicalize specifiers
		Map arpAttributeSpecs =
			createCanonicalAttributeSpec((Rule.Attribute[]) applicableRuleAttributes.toArray(new Rule.Attribute[0]));

		//Filter
		for (ArpAttributeIterator returnIterator = attributes.arpAttributeIterator(); returnIterator.hasNext();) {
			
			ArpAttribute arpAttribute = returnIterator.nextArpAttribute();
			Rule.Attribute attribute = (Rule.Attribute) arpAttributeSpecs.get(arpAttribute.getName());

			//Handle no specifier
			if (attribute == null) {
				returnIterator.remove();
				continue;
			}

			//Handle Deny All
			if (attribute.denyAnyValue()) {
				returnIterator.remove();
				continue;
			}

			//Handle Permit All
			if (attribute.releaseAnyValue() && attribute.getValues().length == 0) {
				continue;
			}

			//Handle "Permit All-Except" and "Permit Specific"
			ArrayList releaseValues = new ArrayList();
			for (Iterator valueIterator = arpAttribute.getValues();valueIterator.hasNext();) {
				Object value = valueIterator.next();
				if (attribute.isValuePermitted(value)) {
					releaseValues.add(value);
				}
			}
			arpAttribute.setValues((Object[]) releaseValues.toArray(new Object[0]));
		}
	}

	private Map createCanonicalAttributeSpec(Rule.Attribute[] attributes) {
		Map canonicalSpec = new HashMap();
		for (int i = 0; attributes.length > i; i++) {
			if (!canonicalSpec.containsKey(attributes[i].getName().toString())) {
				canonicalSpec.put(attributes[i].getName().toString(), attributes[i]);
			} else {
				if (((Rule.Attribute) canonicalSpec.get(attributes[i].getName().toString()))
					.denyAnyValue()) {
					continue;
				}
				if (attributes[i].denyAnyValue()) {
					((Rule.Attribute) canonicalSpec.get(attributes[i].getName().toString())).setAnyValueDeny(
						true);
					continue;
				}
				if (attributes[i].releaseAnyValue()) {
					(
						(Rule.Attribute) canonicalSpec.get(
							attributes[i].getName().toString())).setAnyValuePermit(
						true);
				}
				Rule.AttributeValue[] values = attributes[i].getValues();
				for (int j = 0; values.length > j; j++) {
					((Rule.Attribute) canonicalSpec.get(attributes[i].getName().toString())).addValue(
						values[j]);
				}
			}
		}
		return canonicalSpec;
	}

}
