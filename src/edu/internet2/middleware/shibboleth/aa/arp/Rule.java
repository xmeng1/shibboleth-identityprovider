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
import java.util.ArrayList;
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
 *  An Attribute Release Policy Rule.
 *
 * @author Walter Hoehn (wassa@columbia.edu)
 */

public class Rule {

	private String description;
	private Target target;
	private static Logger log = Logger.getLogger(Rule.class.getName());
	private ArrayList attributes = new ArrayList();
	private NodeList attributeReferences;

	/**
	 * Returns the description for this <code>Rule</code>.
	 * @return String
	 */

	public String getDescription() {
		return description;
	}

	/**
	 * Sets the description for this <code>Rule</code>.
	 * @param description The description to set
	 */

	public void setDescription(String description) {
		this.description = description;
	}

	/**
	 * Returns all of the attribute specifications associated with this Rule.
	 * @return the attributes
	 */

	public Attribute[] getAttributes() {
		return (Attribute[]) attributes.toArray(new Attribute[0]);
	}

	/**
	 * Unmarshalls the <code>Rule</code> into an xml <code>Element</code>.
	 * @return the xml <code>Element</code>
	 */

	public Element unmarshall() throws ArpMarshallingException {

		try {
			Document placeHolder = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
			Element ruleNode = placeHolder.createElementNS(Arp.arpNamespace, "Rule");

			if (description != null) {
				Element descriptionNode = placeHolder.createElementNS(Arp.arpNamespace, "Description");
				descriptionNode.appendChild(placeHolder.createTextNode(description));
				ruleNode.appendChild(descriptionNode);
			}
			ruleNode.appendChild(placeHolder.importNode(target.unmarshall(), true));
			Iterator attrIterator = attributes.iterator();
			while (attrIterator.hasNext()) {
				ruleNode.appendChild(
					placeHolder.importNode(((Attribute) attrIterator.next()).unmarshall(), true));
			}
			
			if (attributeReferences != null) {
				for (int i = 0;i < attributeReferences.getLength();i++) {
					ruleNode.appendChild(
					placeHolder.importNode(attributeReferences.item(i), true));
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
	 * @param element the xml <code>Element</code> containing the ARP Rule.
	 */

	public void marshall(Element element) throws ArpMarshallingException {

		//Make sure we are dealing with a Rule
		if (!element.getTagName().equals("Rule")) {
			log.error("Element data does not represent an ARP Rule.");
			throw new ArpMarshallingException("Element data does not represent an ARP Rule.");
		}

		//Grab the description
		NodeList descriptionNodes = element.getElementsByTagNameNS(Arp.arpNamespace, "Description");
		if (descriptionNodes.getLength() > 0) {
			Element descriptionNode = (Element) descriptionNodes.item(0);
			if (descriptionNode.hasChildNodes()
				&& descriptionNode.getFirstChild().getNodeType() == Node.TEXT_NODE) {
				description = ((CharacterData) descriptionNode.getFirstChild()).getData();
			}
		}

		//Create the Target
		NodeList targetNodes = element.getElementsByTagNameNS(Arp.arpNamespace, "Target");
		if (targetNodes.getLength() != 1) {
			log.error(
				"Element data does not represent an ARP Rule.  An ARP Rule must contain 1 and "
					+ "only 1 Target definition.");
			throw new ArpMarshallingException(
				"Element data does not represent an ARP Rule.  An"
					+ " ARP Rule must contain 1 and only 1 Target definition.");
		}
		target = new Target();
		target.marshall((Element) targetNodes.item(0));

		//Create the Attributes
		NodeList attributeNodes = element.getElementsByTagNameNS(Arp.arpNamespace, "Attribute");
		for (int i = 0; attributeNodes.getLength() > i; i++) {
			Attribute attribute = new Attribute();
			attribute.marshall((Element) attributeNodes.item(i));
			attributes.add(attribute);
		}

		//Retain Attribute references
		//Not enforced!
		NodeList attributeReferenceNodes =
			element.getElementsByTagNameNS(Arp.arpNamespace, "AttributeReference");
		if (attributeReferenceNodes.getLength() > 0) {
			log.warn(
				"Encountered an Attribute Reference while marshalling an ARP.  "
					+ "References are currently unsupported by the ARP Engine.  Ignoring...");
			attributeReferences = attributeReferenceNodes;
		}
	}

	/**
	 * Returns a boolean indication of whether this rule is applicable to a given attribute request.
	 * @param requester the SHAR making the request
	 * @param resource the resource on behalf of which the request is being made
	 */

	public boolean matchesRequest(String requester, URL resource) {
		if (target.matchesAny()) {
			return true;
		}
		try {
			MatchFunction requesterFunction =
				ArpEngine.lookupMatchFunction(target.getRequester().getMatchFunctionIdentifier());
			if (!requesterFunction.match(target.getRequester().getValue(), requester)) {
				return false;
			}
			if (target.getResource().matchesAny()) {
				return true;
			}
			MatchFunction resourceFunction =
				ArpEngine.lookupMatchFunction(target.getResource().getMatchFunctionIdentifier());
			if (resourceFunction.match(target.getResource().getValue(), resource)) {
				return true;
			}
			return false;
		} catch (ArpException e) {
			log.warn("Encountered a problem while trying to find matching ARP rules: " + e);
			return false;
		}
	}

	class Target {
		private Requester requester = null;
		private Resource resource = null;
		private boolean matchesAny = false;

		/**
		 * Unmarshalls the <code>Rule.Target</code> into an xml <code>Element</code>.
		 * @return the xml <code>Element</code>
		 */

		Element unmarshall() throws ArpMarshallingException {

			try {
				Document placeHolder =
					DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
				Element targetNode = placeHolder.createElementNS(Arp.arpNamespace, "Target");

				if (matchesAny) {
					Element anyTargetNode = placeHolder.createElementNS(Arp.arpNamespace, "AnyTarget");
					targetNode.appendChild(anyTargetNode);
					return targetNode;
				}
				targetNode.appendChild(placeHolder.importNode(requester.unmarshall(), true));
				if (target.resource.matchesAny()) {
					Element anyResourceNode = placeHolder.createElementNS(Arp.arpNamespace, "AnyResource");
					targetNode.appendChild(anyResourceNode);
					return targetNode;
				}
				targetNode.appendChild(placeHolder.importNode(resource.unmarshall(), true));
				return targetNode;
			} catch (ParserConfigurationException e) {
				log.error("Encountered a problem unmarshalling an ARP Rule: " + e);
				throw new ArpMarshallingException("Encountered a problem unmarshalling an ARP Rule.");
			}
		}

		/**
		 * Creates an ARP Rule Target from an xml representation.
		 * @param element the xml <code>Element</code> containing the ARP Rule.
		 */
		void marshall(Element element) throws ArpMarshallingException {

			//Make sure we are dealing with a Target
			if (!element.getTagName().equals("Target")) {
				log.error("Element data does not represent an ARP Rule Target.");
				throw new ArpMarshallingException("Element data does not represent an ARP Rule target.");
			}

			//Handle <AnyTarget/> definitions
			NodeList anyTargetNodeList = element.getElementsByTagNameNS(Arp.arpNamespace, "AnyTarget");
			if (anyTargetNodeList.getLength() == 1) {
				matchesAny = true;
				return;
			}

			//Create Requester
			NodeList requesterNodeList = element.getElementsByTagNameNS(Arp.arpNamespace, "Requester");
			if (requesterNodeList.getLength() == 1) {
				requester = new Requester();
				requester.marshall((Element) requesterNodeList.item(0));
			} else {
				log.error("ARP Rule Target contains invalid data: incorrectly specified <Requester>.");
				throw new ArpMarshallingException("ARP Rule Target contains invalid data: incorrectly specified <Requester>.");
			}

			//Handle <AnyResource/>
			NodeList anyResourceNodeList = element.getElementsByTagNameNS(Arp.arpNamespace, "AnyResource");
			if (anyResourceNodeList.getLength() == 1) {
				resource = new Resource();
				return;
			}

			//Create Resource
			NodeList resourceNodeList = element.getElementsByTagNameNS(Arp.arpNamespace, "Resource");
			if (resourceNodeList.getLength() == 1) {
				resource = new Resource();
				resource.marshall((Element) resourceNodeList.item(0));
			} else {
				log.error("ARP Rule Target contains invalid data: incorrectly specified <Resource>.");
				throw new ArpMarshallingException("ARP Rule Target contains invalid data: incorrectly specified <Resource>.");
			}
		}

		boolean matchesAny() {
			return matchesAny;
		}
		Requester getRequester() {
			return requester;
		}
		Resource getResource() {
			return resource;
		}
	}

	class Resource {
		private String value;
		private URI matchFunctionIdentifier;
		private boolean matchesAny;
		Resource() {
			matchesAny = true;
		}
		boolean matchesAny() {
			return matchesAny;
		}
		URI getMatchFunctionIdentifier() {
			return matchFunctionIdentifier;
		}
		String getValue() {
			return value;
		}

		/**
		 * Unmarshalls the <code>Rule.Resource</code> into an xml <code>Element</code>.
		 * @return the xml <code>Element</code>
		 */

		Element unmarshall() throws ArpMarshallingException {

			try {
				Document placeHolder =
					DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
				Element resourceNode = placeHolder.createElementNS(Arp.arpNamespace, "Resource");
				if (!matchFunctionIdentifier
					.equals(new URI("urn:mace:shibboleth:arp:matchFunction:resourceTree"))) {
					resourceNode.setAttributeNS(Arp.arpNamespace, "matchFunction", matchFunctionIdentifier.toString());
				}
				Text valueNode = placeHolder.createTextNode(value);
				resourceNode.appendChild(valueNode);
				return resourceNode;

			} catch (URISyntaxException e) {
				log.error("Encountered a problem unmarshalling an ARP Rule Resource: " + e);
				throw new ArpMarshallingException("Encountered a problem unmarshalling an ARP Rule Resource.");
			} catch (ParserConfigurationException e) {
				log.error("Encountered a problem unmarshalling an ARP Rule Resource: " + e);
				throw new ArpMarshallingException("Encountered a problem unmarshalling an ARP Rule Resource.");
			}
		}

		/**
		 * Creates an ARP Rule Target Resource from an xml representation.
		 * @param element the xml <code>Element</code> containing the ARP Rule.
		 */
		void marshall(Element element) throws ArpMarshallingException {

			matchesAny = false;

			//Make sure we are deling with a Resource
			if (!element.getTagName().equals("Resource")) {
				log.error("Element data does not represent an ARP Rule Target.");
				throw new ArpMarshallingException("Element data does not represent an ARP Rule target.");
			}

			//Grab the value
			if (element.hasChildNodes() && element.getFirstChild().getNodeType() == Node.TEXT_NODE) {
				value = ((CharacterData) element.getFirstChild()).getData();
			} else {
				log.error("Element data does not represent an ARP Rule Target.");
				throw new ArpMarshallingException("Element data does not represent an ARP Rule target.");
			}

			//Grab the match function
			try {
				if (element.hasAttribute("matchFunction")) {
					matchFunctionIdentifier = new URI(element.getAttribute("matchFunction"));
				} else {
					matchFunctionIdentifier = new URI("urn:mace:shibboleth:arp:matchFunction:resourceTree");
				}
			} catch (URISyntaxException e) {
				log.error("ARP match function not identified by a proper URI.");
				throw new ArpMarshallingException("ARP match function not identified by a proper URI.");
			}
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
		 * @return the xml <code>Element</code>
		 */

		Element unmarshall() throws ArpMarshallingException {

			try {
				Document placeHolder =
					DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
				Element requesterNode = placeHolder.createElementNS(Arp.arpNamespace, "Requester");
				if (!matchFunctionIdentifier
					.equals(new URI("urn:mace:shibboleth:arp:matchFunction:exactShar"))) {
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
		 * @param element the xml <code>Element</code> containing the ARP Rule.
		 */
		void marshall(Element element) throws ArpMarshallingException {
			//Make sure we are deling with a Requester
			if (!element.getTagName().equals("Requester")) {
				log.error("Element data does not represent an ARP Rule Target.");
				throw new ArpMarshallingException("Element data does not represent an ARP Rule target.");
			}

			//Grab the value
			if (element.hasChildNodes() && element.getFirstChild().getNodeType() == Node.TEXT_NODE) {
				value = ((CharacterData) element.getFirstChild()).getData();
			} else {
				log.error("Element data does not represent an ARP Rule Target.");
				throw new ArpMarshallingException("Element data does not represent an ARP Rule target.");
			}

			//Grab the match function
			try {
				if (element.hasAttribute("matchFunction")) {
					matchFunctionIdentifier = new URI(element.getAttribute("matchFunction"));
				} else {
					matchFunctionIdentifier = new URI("urn:mace:shibboleth:arp:matchFunction:exactShar");
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
		private Set values = new HashSet();

		boolean releaseAnyValue() {
			if (anyValueRelease.equals("permit")) {
				return anyValue;
			}
			return false;
		}

		boolean denyAnyValue() {
			if (anyValueRelease.equals("deny")) {
				return anyValue;
			}
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
			//Handle Deny All
			if (denyAnyValue()) {
				return false;
			}

			//Handle Permit All with no specific values
			if (releaseAnyValue() && getValues().length == 0) {
				return true;
			}

			//Handle Deny Specific
			Iterator iterator = values.iterator();
			while (iterator.hasNext()) {
				AttributeValue valueSpec = (AttributeValue) iterator.next();
				if (valueSpec.getValue().equals(value) && valueSpec.getRelease().equals("deny")) {
					return false;
				}
			}
			//Handle Permit All with no relevant specific denies
			if (releaseAnyValue()) {
				return true;
			}

			//Handle Permit Specific
			iterator = values.iterator();
			while (iterator.hasNext()) {
				AttributeValue valueSpec = (AttributeValue) iterator.next();
				if (valueSpec.getValue().equals(value) && valueSpec.getRelease().equals("permit")) {
					return true;
				}
			}

			return false;
		}

		void setAnyValuePermit(boolean b) {
			if (b) {
				anyValue = true;
				anyValueRelease = "permit";
				Iterator iterator = values.iterator();
				HashSet permittedValues = new HashSet();
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
		AttributeValue[] getValues() {
			return (AttributeValue[]) values.toArray(new AttributeValue[0]);
		}

		void addValue(AttributeValue value) {
			if (denyAnyValue()) {
				return;
			}
			if (releaseAnyValue() && value.getRelease().equals("permit")) {
				return;
			}
			values.add(value);
		}

		/**
		 * Unmarshalls an <code>Attribute</code> into an xml <code>Element</code>.
		 * @return the xml <code>Element</code>
		 */

		Element unmarshall() throws ArpMarshallingException {

			try {
				Document placeHolder =
					DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
				Element attributeNode = placeHolder.createElementNS(Arp.arpNamespace, "Attribute");

				attributeNode.setAttributeNS(Arp.arpNamespace, "name", name.toString());
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
					Text valueTextNode = placeHolder.createTextNode(value.getValue());
					valueNode.appendChild(valueTextNode);
					attributeNode.appendChild(valueNode);
				}
				return attributeNode;

			} catch (ParserConfigurationException e) {
				log.error("Encountered a problem unmarshalling an ARP Rule: " + e);
				throw new ArpMarshallingException("Encountered a problem unmarshalling an ARP Rule.");
			}
		}
		
		/**
		 * Creates an ARP Rule Attribute from an xml representation.
		 * @param element the xml <code>Element</code> containing the ARP Rule.
		 */
		void marshall(Element element) throws ArpMarshallingException {
			//Make sure we are dealing with an Attribute
			if (!element.getTagName().equals("Attribute")) {
				log.error("Element data does not represent an ARP Rule Target.");
				throw new ArpMarshallingException("Element data does not represent an ARP Rule target.");
			}

			//Get the attribute name
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

			//Handle <AnyValue/> definitions
			NodeList anyValueNodeList = element.getElementsByTagNameNS(Arp.arpNamespace, "AnyValue");
			if (anyValueNodeList.getLength() == 1) {
				anyValue = true;
				if (((Element) anyValueNodeList.item(0)).hasAttribute("release")) {
					anyValueRelease = ((Element) anyValueNodeList.item(0)).getAttribute("release");
				}
			}

			//Handle Value definitions
			if (!denyAnyValue()) {
				NodeList valueNodeList = element.getElementsByTagNameNS(Arp.arpNamespace, "Value");
				for (int i = 0; valueNodeList.getLength() > i; i++) {
					String release = null;
					String value = null;
					if (((Element) valueNodeList.item(i)).hasAttribute("release")) {
						release = ((Element) valueNodeList.item(i)).getAttribute("release");
					}
					if (((Element) valueNodeList.item(i)).hasChildNodes()
						&& ((Element) valueNodeList.item(i)).getFirstChild().getNodeType() == Node.TEXT_NODE) {
						value = ((CharacterData) ((Element) valueNodeList.item(i)).getFirstChild()).getData();
					}
					if (releaseAnyValue() && release.equals("permit")) {
						continue;
					}
					AttributeValue aValue = new AttributeValue(release, value);
					values.add(aValue);
				}
			}

		}
	}
	class AttributeValue {
		private String release = "permit";
		private String value;

		AttributeValue(String release, String value) {
			setRelease(release);
			this.value = value;
		}

		String getRelease() {
			return release;
		}

		String getValue() {
			return value;
		}

		void setRelease(String release) {
			if (release == null) {
				return;
			}
			if (release.equals("permit") || release.equals("deny")) {
				this.release = release;
			}
		}

		void setValue(String value) {
			this.value = value;
		}
	}

}
