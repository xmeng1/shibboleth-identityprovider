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

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.apache.log4j.Logger;

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

	URI[] listPossibleReleaseAttributes(Principal principal, String requester, URL resource)
		throws ArpProcessingException {
		Set possibleReleaseSet = new HashSet();
		Rule[] rules = createEffectiveArp(principal, requester, resource).getAllRules();
		for (int i = 0; rules.length > i; i++) {
			Rule.Attribute[] attributes = rules[i].getAttributes();
			for (int j = 0; attributes.length > j; j++) {
				if (attributes[j].releaseAnyValue()) {
					possibleReleaseSet.add(attributes[j].getName());
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
		return (URI[]) possibleReleaseSet.toArray(new URI[0]);
	}

}
