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
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.log4j.Logger;
import org.w3c.dom.CharacterData;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

/**
 * An Attribute Release Policy Rule.
 * 
 * @author Walter Hoehn (wassa@memphis.edu)
 */

public class Rule {

	private String description;
	private Target target;
	private static Logger log = Logger.getLogger(Rule.class.getName());
	private ArrayList<Attribute> attributes = new ArrayList<Attribute>();
	private NodeList attributeReferences;

	private URI identifier;

	/**
	 * Returns the description for this <code>Rule</code>.
	 * 
	 * @return String
	 */

	public String getDescription() {

		return description;
	}

	/**
	 * Sets the description for this <code>Rule</code>.
	 * 
	 * @param description
	 *            The description to set
	 */

	public void setDescription(String description) {

		this.description = description;
	}

	/**
	 * Returns all of the attribute specifications associated with this Rule.
	 * 
	 * @return the attributes
	 */

	public Collection<Attribute> getAttributes() {

		return attributes;
	}

	/**
	 * Unmarshalls the <code>Rule</code> into an xml <code>Element</code>.
	 * 
	 * @return the xml <code>Element</code>
	 */

	public Element unmarshall() throws ArpMarshallingException {

		try {
			Document placeHolder = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
			Element ruleNode = placeHolder.createElementNS(Arp.arpNamespace, "Rule");

			if (identifier != null) {
				ruleNode.setAttributeNS(Arp.arpNamespace, "identifier", identifier.toString());
			}

			if (description != null) {
				Element descriptionNode = placeHolder.createElementNS(Arp.arpNamespace, "Description");
				descriptionNode.appendChild(placeHolder.createTextNode(description));
				ruleNode.appendChild(descriptionNode);
			}
			ruleNode.appendChild(placeHolder.importNode(target.unmarshall(), true));
			Iterator attrIterator = attributes.iterator();
			while (attrIterator.hasNext()) {
				ruleNode.appendChild(placeHolder.importNode(((Attribute) attrIterator.next()).unmarshall(), true));
			}

			if (attributeReferences != null) {
				for (int i = 0; i < attributeReferences.getLength(); i++) {
					ruleNode.appendChild(placeHolder.importNode(attributeReferences.item(i), true));
				}
			}
			return ruleNode;
		} catch (ParserConfigurationException e) {
			log.error("Encountered a problem unmarshalling an ARP Rule: " + e);
			throw new ArpMarshallingException("Encountered a problem unmarshalling an ARP Rule.");
		}
	}

	/**
	 * Creates an ARP Rule from an xml representation.
	 * 
	 * @param element
	 *            the xml <code>Element</code> containing the ARP Rule.
	 */

	public void marshall(Element element) throws ArpMarshallingException {

		// Make sure we are dealing with a Rule
		if (!element.getTagName().equals("Rule")) {
			log.error("Element data does not represent an ARP Rule.");
			throw new ArpMarshallingException("Element data does not represent an ARP Rule.");
		}

		// Get the rule identifier
		try {
			if (element.hasAttribute("identifier")) {
				identifier = new URI(element.getAttribute("identifier"));
			}
		} catch (URISyntaxException e) {
			log.error("Rule not identified by a proper URI: " + e);
			throw new ArpMarshallingException("Rule not identified by a proper URI.");
		}

		// Grab the description
		NodeList descriptionNodes = element.getElementsByTagNameNS(Arp.arpNamespace, "Description");
		if (descriptionNodes.getLength() > 0) {
			Element descriptionNode = (Element) descriptionNodes.item(0);
			if (descriptionNode.hasChildNodes() && descriptionNode.getFirstChild().getNodeType() == Node.TEXT_NODE) {
				description = ((CharacterData) descriptionNode.getFirstChild()).getData();
			}
		}

		// Create the Target
		NodeList targetNodes = element.getElementsByTagNameNS(Arp.arpNamespace, "Target");
		if (targetNodes.getLength() != 1) {
			log.error("Element data does not represent an ARP Rule.  An ARP Rule must contain 1 and "
					+ "only 1 Target definition.");
			throw new ArpMarshallingException("Element data does not represent an ARP Rule.  An"
					+ " ARP Rule must contain 1 and only 1 Target definition.");
		}
		target = new Target();
		target.marshall((Element) targetNodes.item(0));

		// Create the Attributes
		NodeList attributeNodes = element.getElementsByTagNameNS(Arp.arpNamespace, "Attribute");
		for (int i = 0; attributeNodes.getLength() > i; i++) {
			Attribute attribute = new Attribute();
			attribute.marshall((Element) attributeNodes.item(i));
			attributes.add(attribute);
		}

		// Retain Attribute references
		// Not enforced!
		NodeList attributeReferenceNodes = element.getElementsByTagNameNS(Arp.arpNamespace, "AttributeReference");
		if (attributeReferenceNodes.getLength() > 0) {
			log.warn("Encountered an Attribute Reference while marshalling an ARP.  "
					+ "References are currently unsupported by the ARP Engine.  Ignoring...");
			attributeReferences = attributeReferenceNodes;
		}
	}

	/**
	 * Returns a boolean indication of whether this rule is applicable to a given attribute request.
	 * 
	 * @param requester
	 *            the SHAR making the request
	 */

	public boolean matchesRequest(String requester) {

		if (target.matchesAny()) { return true; }

		if (requester == null) { return false; }

		try {
			MatchFunction requesterFunction = ArpEngine.lookupMatchFunction(target.getRequester()
					.getMatchFunctionIdentifier());
			if (requesterFunction.match(target.getRequester().getValue(), requester)) {
				return true;
			} else {
				return false;
			}
		} catch (ArpException e) {
			log.warn("Encountered a problem while trying to find matching ARP rules: " + e);
			return false;
		}
	}

	class Target {

		private Requester requester = null;
		private boolean matchesAny = false;

		/**
		 * Unmarshalls the <code>Rule.Target</code> into an xml <code>Element</code>.
		 * 
		 * @return the xml <code>Element</code>
		 */

		Element unmarshall() throws ArpMarshallingException {

			try {
				Document placeHolder = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
				Element targetNode = placeHolder.createElementNS(Arp.arpNamespace, "Target");

				if (matchesAny) {
					Element anyTargetNode = placeHolder.createElementNS(Arp.arpNamespace, "AnyTarget");
					targetNode.appendChild(anyTargetNode);
					return targetNode;
				}
				targetNode.appendChild(placeHolder.importNode(requester.unmarshall(), true));
				return targetNode;
			} catch (ParserConfigurationException e) {
				log.error("Encountered a problem unmarshalling an ARP Rule: " + e);
				throw new ArpMarshallingException("Encountered a problem unmarshalling an ARP Rule.");
			}
		}

		/**
		 * Creates an ARP Rule Target from an xml representation.
		 * 
		 * @param element
		 *            the xml <code>Element</code> containing the ARP Rule.
		 */
		void marshall(Element element) throws ArpMarshallingException {

			// Make sure we are dealing with a Target
			if (!element.getTagName().equals("Target")) {
				log.error("Element data does not represent an ARP Rule Target.");
				throw new ArpMarshallingException("Element data does not represent an ARP Rule target.");
			}

			// Handle <AnyTarget/> definitions
			NodeList anyTargetNodeList = element.getElementsByTagNameNS(Arp.arpNamespace, "AnyTarget");
			if (anyTargetNodeList.getLength() == 1) {
				matchesAny = true;
				return;
			}

			// Create Requester
			NodeList requesterNodeList = element.getElementsByTagNameNS(Arp.arpNamespace, "Requester");
			if (requesterNodeList.getLength() == 1) {
				requester = new Requester();
				requester.marshall((Element) requesterNodeList.item(0));
			} else {
				log.error("ARP Rule Target contains invalid data: incorrectly specified <Requester>.");
				throw new ArpMarshallingException(
						"ARP Rule Target contains invalid data: incorrectly specified <Requester>.");
			}
		}

		boolean matchesAny() {

			return matchesAny;
		}

		Requester getRequester() {

			return requester;
		}
	}

	class Requester {

		private String value;
		private URI matchFunctionIdentifier;

		URI getMatchFunctionIdentifier() {

			return matchFunctionIdentifier;
		}

		String getValue() {

			return value;
		}

		/**
		 * Unmarshalls the <code>Rule.Requester</code> into an xml <code>Element</code>.
		 * 
		 * @return the xml <code>Element</code>
		 */

		Element unmarshall() throws ArpMarshallingException {

			try {
				Document placeHolder = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
				Element requesterNode = placeHolder.createElementNS(Arp.arpNamespace, "Requester");
				if (!matchFunctionIdentifier.equals(new URI("urn:mace:shibboleth:arp:matchFunction:stringMatch"))) {
					requesterNode.setAttributeNS(Arp.arpNamespace, "matchFunction", matchFunctionIdentifier.toString());
				}
				Text valueNode = placeHolder.createTextNode(value);
				requesterNode.appendChild(valueNode);
				return requesterNode;

			} catch (URISyntaxException e) {
				log.error("Encountered a problem unmarshalling an ARP Rule Requester: " + e);
				throw new ArpMarshallingException("Encountered a problem unmarshalling an ARP Rule Requester.");
			} catch (ParserConfigurationException e) {
				log.error("Encountered a problem unmarshalling an ARP Rule Requester: " + e);
				throw new ArpMarshallingException("Encountered a problem unmarshalling an ARP Rule Requester.");
			}
		}

		/**
		 * Creates an ARP Rule Target Requester from an xml representation.
		 * 
		 * @param element
		 *            the xml <code>Element</code> containing the ARP Rule.
		 */
		void marshall(Element element) throws ArpMarshallingException {

			// Make sure we are deling with a Requester
			if (!element.getTagName().equals("Requester")) {
				log.error("Element data does not represent an ARP Rule Target.");
				throw new ArpMarshallingException("Element data does not represent an ARP Rule target.");
			}

			// Grab the value
			if (element.hasChildNodes() && element.getFirstChild().getNodeType() == Node.TEXT_NODE) {
				value = ((CharacterData) element.getFirstChild()).getData();
			} else {
				log.error("Element data does not represent an ARP Rule Target.");
				throw new ArpMarshallingException("Element data does not represent an ARP Rule target.");
			}

			// Grab the match function
			try {
				if (element.hasAttribute("matchFunction")) {
					matchFunctionIdentifier = new URI(element.getAttribute("matchFunction"));
				} else {
					matchFunctionIdentifier = new URI("urn:mace:shibboleth:arp:matchFunction:stringMatch");
				}
			} catch (URISyntaxException e) {
				log.error("ARP match function not identified by a proper URI.");
				throw new ArpMarshallingException("ARP match function not identified by a proper URI.");
			}
		}
	}

	class Attribute {

		private URI name;
		private boolean anyValue = false;
		private String anyValueRelease = "permit";
		private Set<AttributeValue> values = new HashSet<AttributeValue>();
		private URI identifier;

		boolean releaseAnyValue() {

			if (anyValueRelease.equals("permit")) { return anyValue; }
			return false;
		}

		boolean denyAnyValue() {

			if (anyValueRelease.equals("deny")) { return anyValue; }
			return false;
		}

		void setAnyValueDeny(boolean b) {

			if (b) {
				anyValue = true;
				anyValueRelease = "deny";
				values.clear();
			} else {
				if (anyValueRelease.equals("deny") && anyValue) {
					anyValue = false;
				}
			}
		}

		boolean isValuePermitted(Object value) {

			// Handle Deny All
			if (denyAnyValue()) { return false; }

			// Handle Permit All with no specific values
			if (releaseAnyValue() && getValues().size() == 0) { return true; }

			// Handle Deny Specific
			Iterator iterator = values.iterator();
			while (iterator.hasNext()) {
				AttributeValue valueSpec = (AttributeValue) iterator.next();

				MatchFunction resourceFunction;
				try {
					resourceFunction = ArpEngine.lookupMatchFunction(valueSpec.getMatchFunctionIdentifier());
					// For safety, err on the side of caution
					if (resourceFunction == null) {
						log.warn("Could not locate matching function for ARP value. Function: "
								+ valueSpec.getMatchFunctionIdentifier().toString());
						return false;
					}

				} catch (ArpException e) {
					log.error("Error while attempting to find referenced matching function for ARP values: " + e);
					return false;
				}

				try {
					if (valueSpec.getRelease().equals("deny") && resourceFunction.match(valueSpec.getValue(), value)) { return false; }
				} catch (MatchingException e) {
					log.error("Could not apply referenced matching function to ARP value: " + e);
					return false;
				}
			}

			// Handle Permit All with no relevant specific denies
			if (releaseAnyValue()) { return true; }

			// Handle Permit Specific
			iterator = values.iterator();
			while (iterator.hasNext()) {
				AttributeValue valueSpec = (AttributeValue) iterator.next();

				MatchFunction resourceFunction;
				try {
					resourceFunction = ArpEngine.lookupMatchFunction(valueSpec.getMatchFunctionIdentifier());
					// Ignore non-functional permits
					if (resourceFunction == null) {
						log.warn("Could not locate matching function for ARP value. Function: "
								+ valueSpec.getMatchFunctionIdentifier().toString());
						continue;
					}

				} catch (ArpException e) {
					log.error("Error while attempting to find referenced matching function for ARP values: " + e);
					continue;
				}

				try {
					if (valueSpec.getRelease().equals("permit") && resourceFunction.match(valueSpec.getValue(), value)) { return true; }
				} catch (MatchingException e) {
					log.error("Could not apply referenced matching function to ARP value: " + e);
					continue;
				}
			}
			return false;
		}

		void setAnyValuePermit(boolean b) {

			if (b) {
				anyValue = true;
				anyValueRelease = "permit";
				Iterator<AttributeValue> iterator = values.iterator();
				Set<AttributeValue> permittedValues = new HashSet<AttributeValue>();
				while (iterator.hasNext()) {
					AttributeValue value = (AttributeValue) iterator.next();
					if (value.getRelease().equals("permit")) {
						permittedValues.add(value);
					}
				}
				values.removeAll(permittedValues);
			} else {
				if (anyValueRelease.equals("permit") && anyValue) {
					anyValue = false;
				}
			}
		}

		URI getName() {

			return name;
		}

		Collection<AttributeValue> getValues() {

			return values;
		}

		void addValue(AttributeValue value) {

			if (denyAnyValue()) { return; }
			if (releaseAnyValue() && value.getRelease().equals("permit")) { return; }
			values.add(value);
		}

		/**
		 * Unmarshalls an <code>Attribute</code> into an xml <code>Element</code>.
		 * 
		 * @return the xml <code>Element</code>
		 */

		Element unmarshall() throws ArpMarshallingException {

			try {
				Document placeHolder = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
				Element attributeNode = placeHolder.createElementNS(Arp.arpNamespace, "Attribute");

				attributeNode.setAttributeNS(Arp.arpNamespace, "name", name.toString());

				if (identifier != null) {
					attributeNode.setAttributeNS(Arp.arpNamespace, "identifier", identifier.toString());
				}

				if (anyValue) {
					Element anyValueNode = placeHolder.createElementNS(Arp.arpNamespace, "AnyValue");
					anyValueNode.setAttributeNS(Arp.arpNamespace, "release", anyValueRelease);
					attributeNode.appendChild(anyValueNode);
				}
				Iterator valueIterator = values.iterator();
				while (valueIterator.hasNext()) {
					AttributeValue value = (AttributeValue) valueIterator.next();
					Element valueNode = placeHolder.createElementNS(Arp.arpNamespace, "Value");
					valueNode.setAttributeNS(Arp.arpNamespace, "release", value.getRelease());
					if (!value.getMatchFunctionIdentifier().equals(
							new URI("urn:mace:shibboleth:arp:matchFunction:stringMatch"))) {
						valueNode.setAttributeNS(Arp.arpNamespace, "matchFunction", value.getMatchFunctionIdentifier()
								.toString());
					}
					Text valueTextNode = placeHolder.createTextNode(value.getValue());
					valueNode.appendChild(valueTextNode);
					attributeNode.appendChild(valueNode);
				}
				return attributeNode;

			} catch (URISyntaxException e) {
				log.error("Encountered a problem unmarshalling an ARP Rule Resource: " + e);
				throw new ArpMarshallingException("Encountered a problem unmarshalling an ARP Rule Resource.");
			} catch (ParserConfigurationException e) {
				log.error("Encountered a problem unmarshalling an ARP Rule: " + e);
				throw new ArpMarshallingException("Encountered a problem unmarshalling an ARP Rule.");
			}
		}

		/**
		 * Creates an ARP Rule Attribute from an xml representation.
		 * 
		 * @param element
		 *            the xml <code>Element</code> containing the ARP Rule.
		 */
		void marshall(Element element) throws ArpMarshallingException {

			// Make sure we are dealing with an Attribute
			if (!element.getTagName().equals("Attribute")) {
				log.error("Element data does not represent an ARP Rule Target.");
				throw new ArpMarshallingException("Element data does not represent an ARP Rule target.");
			}

			// Get the attribute identifier
			try {
				if (element.hasAttribute("identifier")) {
					identifier = new URI(element.getAttribute("identifier"));
				}
			} catch (URISyntaxException e) {
				log.error("Attribute not identified by a proper URI: " + e);
				throw new ArpMarshallingException("Attribute not identified by a proper URI.");
			}

			// Get the attribute name
			try {
				if (element.hasAttribute("name")) {
					name = new URI(element.getAttribute("name"));
				} else {
					log.error("Attribute name not specified.");
					throw new ArpMarshallingException("Attribute name not specified.");
				}
			} catch (URISyntaxException e) {
				log.error("Attribute name not identified by a proper URI: " + e);
				throw new ArpMarshallingException("Attribute name not identified by a proper URI.");
			}

			// Handle <AnyValue/> definitions
			NodeList anyValueNodeList = element.getElementsByTagNameNS(Arp.arpNamespace, "AnyValue");
			if (anyValueNodeList.getLength() == 1) {
				anyValue = true;
				if (((Element) anyValueNodeList.item(0)).hasAttribute("release")) {
					anyValueRelease = ((Element) anyValueNodeList.item(0)).getAttribute("release");
				}
			}

			// Handle Value definitions
			if (!denyAnyValue()) {
				NodeList valueNodeList = element.getElementsByTagNameNS(Arp.arpNamespace, "Value");
				for (int i = 0; valueNodeList.getLength() > i; i++) {
					String release = null;
					String value = null;
					URI matchFunctionIdentifier = null;
					if (((Element) valueNodeList.item(i)).hasAttribute("release")) {
						release = ((Element) valueNodeList.item(i)).getAttribute("release");
					}

					// Grab the match function
					try {
						if (((Element) valueNodeList.item(i)).hasAttribute("matchFunction")) {
							matchFunctionIdentifier = new URI(((Element) valueNodeList.item(i))
									.getAttribute("matchFunction"));
						}
					} catch (URISyntaxException e) {
						log.error("ARP match function not identified by a proper URI: "
								+ ((Element) valueNodeList.item(i)).getAttribute("matchFunction"));
						throw new ArpMarshallingException("ARP match function not identified by a proper URI.");
					}

					if (((Element) valueNodeList.item(i)).hasChildNodes()
							&& ((Element) valueNodeList.item(i)).getFirstChild().getNodeType() == Node.TEXT_NODE) {
						value = ((CharacterData) ((Element) valueNodeList.item(i)).getFirstChild()).getData();
					}
					if (releaseAnyValue() && release.equals("permit")) {
						continue;
					}
					AttributeValue aValue = new AttributeValue(release, matchFunctionIdentifier, value);
					values.add(aValue);
				}
			}

		}
	}

	class AttributeValue {

		private String release = "permit";
		private String value;
		private URI matchFunctionIdentifier;

		AttributeValue(String release, URI matchFunctionIdentifier, String value) throws ArpMarshallingException {

			setRelease(release);
			this.value = value;
			if (matchFunctionIdentifier != null) {
				this.matchFunctionIdentifier = matchFunctionIdentifier;
			} else {
				try {
					this.matchFunctionIdentifier = new URI("urn:mace:shibboleth:arp:matchFunction:stringMatch");
				} catch (URISyntaxException e) {
					throw new ArpMarshallingException(
							"ARP Engine internal error: could not set default matching function for attribute value.");
				}
			}
		}

		String getRelease() {

			return release;
		}

		String getValue() {

			return value;
		}

		URI getMatchFunctionIdentifier() {

			return matchFunctionIdentifier;
		}

		void setRelease(String release) {

			if (release == null) { return; }
			if (release.equals("permit") || release.equals("deny")) {
				this.release = release;
			}
		}

		void setValue(String value) {

			this.value = value;
		}
	}

}
