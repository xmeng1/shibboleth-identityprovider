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

import java.net.URL;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.log4j.Logger;
import org.w3c.dom.CharacterData;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 *  An Attribute Release Policy.
 *
 * @author Walter Hoehn (wassa@columbia.edu)
 */

public class Arp {

	public static final String arpNamespace = "urn:mace:shibboleth:arp:1.0";
	private Principal principal;
	private List rules = new ArrayList();
	private String description;
	private boolean sitePolicy = false;
	private static Logger log = Logger.getLogger(Arp.class.getName());
	private Set attributes = new HashSet();

	/**
	 * Creates an Arp for the specified <code>Principal</code>.
	 */

	public Arp(Principal principal) {
		this.principal = principal;
	}

	/**
	 * Creates a "Site" Policy.
	 */

	public Arp() {
		sitePolicy = true;
	}

	/**
	 * Boolean indication of whether or not this Policy is a "Site" policy.
	 */

	public boolean isSitePolicy() {
		return sitePolicy;
	}

	/**
	 * Returns the <code>Principal</code> for which this policy is applicable.
	 * @return Principal
	 */

	public Principal getPrincipal() {
		return principal;
	}

	/**
	 * Specify the <code>Principal</code> for which this policy is applicable.
	 * @param principal The principal
	 */

	public void setPrincipal(Principal principal) {
		sitePolicy = false;
		this.principal = principal;
	}

	/**
	 * Creates an ARP structure from an xml representation.
	 * @param the xml <code>Element</code> containing the ARP structure.
	 */

	void marshall(Element xmlElement) throws ArpMarshallingException {

		//Make sure we are deling with an ARP
		if (!xmlElement.getTagName().equals("AttributeReleasePolicy")) {
			throw new ArpMarshallingException("Element data does not represent an ARP.");
		}

		//Grab the description
		NodeList descriptionNodes = xmlElement.getElementsByTagNameNS(arpNamespace, "Description");
		if (descriptionNodes.getLength() > 0) {
			Element descriptionNode = (Element) descriptionNodes.item(0);
			if (descriptionNode.hasChildNodes()
				&& descriptionNode.getFirstChild().getNodeType() == Node.TEXT_NODE) {
				description = ((CharacterData) descriptionNode.getFirstChild()).getData();
			}
		}

		//Grab all of the Rule Elements and marshall them
		NodeList ruleNodes = xmlElement.getElementsByTagNameNS(arpNamespace, "Rule");
		if (ruleNodes.getLength() > 0) {
			for (int i = 0; i < ruleNodes.getLength(); i++) {
				Rule rule = new Rule();
				try {
					rule.marshall((Element) ruleNodes.item(i));
				} catch (ArpMarshallingException me) {
					throw new ArpMarshallingException(
						"Encountered a problem marshalling ARP Rules: " + me);
				}
				rules.add(rule);
			}

			//Retain attributes declared outside the scop of a rule
			//Not enforced!
			NodeList attributeNodes =
				xmlElement.getElementsByTagNameNS(Arp.arpNamespace, "Attribute");
			if (attributeNodes.getLength() > 0) {
				for (int i = 0; i < attributeNodes.getLength(); i++) {
					if (attributeNodes.item(i).getParentNode() == xmlElement) {
						log.warn(
							"Encountered an Attribute definition outside the scope of a Rule definition while marshalling an ARP.  "
								+ "References are currently unsupported by the ARP Engine.  Ignoring...");
						attributes.add(attributeNodes.item(i));
					}
				}
			}
		}
	}

	/**
	 * Unmarshalls the <code>Arp</code> into an xml <code>Element</code>.
	 * @return the xml <code>Element</code>
	 */

	Element unmarshall() throws ArpMarshallingException {

		try {
			DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
			docFactory.setNamespaceAware(true);
			Document placeHolder = docFactory.newDocumentBuilder().newDocument();

			Element policyNode =
				placeHolder.createElementNS(arpNamespace, "AttributeReleasePolicy");
			policyNode.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns", arpNamespace);
			policyNode.setAttributeNS(
				"http://www.w3.org/2000/xmlns/",
				"xmlns:xsi",
				"http://www.w3.org/2001/XMLSchema-instance");
			policyNode.setAttributeNS(
				"http://www.w3.org/2001/XMLSchema-instance",
				"xsi:schemaLocation",
				"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd");
			if (description != null) {
				Element descriptionNode = placeHolder.createElementNS(arpNamespace, "Description");
				descriptionNode.appendChild(placeHolder.createTextNode(description));
				policyNode.appendChild(descriptionNode);
			}

			Rule[] rules = getAllRules();
			for (int i = 0; rules.length > i; i++) {
				policyNode.appendChild(placeHolder.importNode(rules[i].unmarshall(), true));
			}

			Iterator attrIterator = attributes.iterator();
			while (attrIterator.hasNext()) {
				policyNode.appendChild(placeHolder.importNode((Node) attrIterator.next(), true));
			}

			return policyNode;

		} catch (ParserConfigurationException e) {
			log.error("Encountered a problem unmarshalling an ARP: " + e);
			throw new ArpMarshallingException("Encountered a problem unmarshalling an ARP.");
		}

	}

	/**
	 * Returns all of the <code>Rule</code> objects that make up this policy.
	 * @return the rules 
	 */

	public Rule[] getAllRules() {

		return (Rule[]) rules.toArray(new Rule[0]);
	}

	/**
	 * Returns the description for this <code>Arp</code> or null if no description is set.
	 * @return String
	 */

	public String getDescription() {
		return description;
	}

	/**
	 * Sets the description for this <code>Arp</code>.
	 * @param description The description to set
	 */

	public void setDescription(String description) {
		this.description = description;
	}

	/**
	 * Finds all of the rules contained in the <code>Arp</code> object that are applicable 
	 * to a particular request.
	 * @param requester the SHAR for this request
	 * @param resource the resource that the requestis made on behalf of
	 * @return the matching <code>Rule</code> objects
	 */
	public Rule[] getMatchingRules(String requester, URL resource) {
		Set effectiveSet = new HashSet();
		Iterator iterator = rules.iterator();
		while (iterator.hasNext()) {
			Rule rule = (Rule) iterator.next();
			if (rule.matchesRequest(requester, resource)) {
				effectiveSet.add(rule);
			}
		}
		return (Rule[]) effectiveSet.toArray(new Rule[0]);
	}

	/**
	 * Adds an ARP Rule to this <code>ARP</code>.
	 * @param rule the <code>Rule</code> to add
	 */
	public void addRule(Rule rule) {
		rules.add(rule);
	}

}
