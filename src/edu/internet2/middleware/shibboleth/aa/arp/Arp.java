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

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.log4j.Logger;
import org.w3c.dom.CharacterData;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * An Attribute Release Policy.
 * 
 * @author Walter Hoehn (wassa@memphis.edu)
 */

public class Arp {

	public static final String arpNamespace = "urn:mace:shibboleth:arp:1.0";
	private Principal principal;
	private List<Rule> rules = new ArrayList<Rule>();
	private String description;
	private boolean sitePolicy = false;
	private static Logger log = Logger.getLogger(Arp.class.getName());
	private List<Node> attributes = new ArrayList<Node>();

	private NodeList ruleReferences;

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
	 * 
	 * @return Principal
	 */

	public Principal getPrincipal() {

		return principal;
	}

	/**
	 * Specify the <code>Principal</code> for which this policy is applicable.
	 * 
	 * @param principal
	 *            The principal
	 */

	public void setPrincipal(Principal principal) {

		sitePolicy = false;
		this.principal = principal;
	}

	/**
	 * Creates an ARP structure from an xml representation.
	 * 
	 * @param the
	 *            xml <code>Element</code> containing the ARP structure.
	 */

	public void marshall(Element xmlElement) throws ArpMarshallingException {

		// Make sure we are deling with an ARP
		if (!xmlElement.getTagName().equals("AttributeReleasePolicy")) { throw new ArpMarshallingException(
				"Element data does not represent an ARP."); }

		// Grab the description
		NodeList descriptionNodes = xmlElement.getElementsByTagNameNS(arpNamespace, "Description");
		if (descriptionNodes.getLength() > 0) {
			Element descriptionNode = (Element) descriptionNodes.item(0);
			if (descriptionNode.hasChildNodes() && descriptionNode.getFirstChild().getNodeType() == Node.TEXT_NODE) {
				description = ((CharacterData) descriptionNode.getFirstChild()).getData();
			}
		}

		// Grab all of the Rule Elements and marshall them
		NodeList ruleNodes = xmlElement.getElementsByTagNameNS(arpNamespace, "Rule");
		if (ruleNodes.getLength() > 0) {
			for (int i = 0; i < ruleNodes.getLength(); i++) {
				Rule rule = new Rule();
				try {
					rule.marshall((Element) ruleNodes.item(i));
				} catch (ArpMarshallingException me) {
					throw new ArpMarshallingException("Encountered a problem marshalling ARP Rules: " + me);
				}
				rules.add(rule);
			}

		}

		// Retain Rule references
		// Not enforced!
		NodeList ruleReferenceNodes = xmlElement.getElementsByTagNameNS(arpNamespace, "RuleReference");
		if (ruleReferenceNodes.getLength() > 0) {
			log.warn("Encountered a Rule Reference while marshalling an ARP.  "
					+ "References are currently unsupported by the ARP Engine.  Ignoring...");
			ruleReferences = ruleReferenceNodes;
		}

		// Retain attributes declared outside the scope of a rule
		// Not enforced!
		NodeList attributeNodes = xmlElement.getElementsByTagNameNS(Arp.arpNamespace, "Attribute");
		if (attributeNodes.getLength() > 0) {
			for (int i = 0; i < attributeNodes.getLength(); i++) {
				if (attributeNodes.item(i).getParentNode() == xmlElement) {
					log.warn("Encountered an Attribute definition outside the scope of a Rule "
							+ "definition while marshalling an ARP.  "
							+ "References are currently unsupported by the ARP Engine.  Ignoring...");
					attributes.add(attributeNodes.item(i));
				}
			}
		}
	}

	/**
	 * Unmarshalls the <code>Arp</code> into an xml <code>Element</code>.
	 * 
	 * @return the xml <code>Element</code>
	 */

	public Element unmarshall() throws ArpMarshallingException {

		try {
			DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
			docFactory.setNamespaceAware(true);
			Document placeHolder = docFactory.newDocumentBuilder().newDocument();

			Element policyNode = placeHolder.createElementNS(arpNamespace, "AttributeReleasePolicy");
			policyNode.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns", arpNamespace);
			policyNode.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:xsi",
					"http://www.w3.org/2001/XMLSchema-instance");
			policyNode.setAttributeNS("http://www.w3.org/2001/XMLSchema-instance", "xsi:schemaLocation",
					"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd");
			if (description != null) {
				Element descriptionNode = placeHolder.createElementNS(arpNamespace, "Description");
				descriptionNode.appendChild(placeHolder.createTextNode(description));
				policyNode.appendChild(descriptionNode);
			}

			Collection<Rule> rules = getAllRules();
			for (Rule rule : rules) {
				policyNode.appendChild(placeHolder.importNode(rule.unmarshall(), true));
			}

			if (ruleReferences != null) {
				for (int i = 0; i < ruleReferences.getLength(); i++) {
					policyNode.appendChild(placeHolder.importNode(ruleReferences.item(i), true));
				}
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
	 * 
	 * @return the rules
	 */

	public Collection<Rule> getAllRules() {

		return rules;
	}

	/**
	 * Returns the description for this <code>Arp</code> or null if no description is set.
	 * 
	 * @return String
	 */

	public String getDescription() {

		return description;
	}

	/**
	 * Sets the description for this <code>Arp</code>.
	 * 
	 * @param description
	 *            The description to set
	 */

	public void setDescription(String description) {

		this.description = description;
	}

	/**
	 * Finds all of the rules contained in the <code>Arp</code> object that are applicable to a particular request.
	 * 
	 * @param requester
	 *            the SHAR for this request
	 * @return the matching <code>Rule</code> objects
	 */
	public Collection<Rule> getMatchingRules(String requester) {

		List<Rule> effectiveSet = new ArrayList<Rule>();
		Iterator iterator = rules.iterator();
		while (iterator.hasNext()) {
			Rule rule = (Rule) iterator.next();
			if (rule.matchesRequest(requester)) {
				effectiveSet.add(rule);
			}
		}
		return effectiveSet;
	}

	/**
	 * Adds an ARP Rule to this <code>ARP</code>.
	 * 
	 * @param rule
	 *            the <code>Rule</code> to add
	 */
	public void addRule(Rule rule) {

		rules.add(rule);
	}

}
