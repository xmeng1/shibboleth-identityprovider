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

import org.apache.log4j.Logger;
import org.apache.xerces.parsers.DOMParser;
import org.w3c.dom.CharacterData;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 *  An Attribute Release Policy Rule.
 *
 * @author Walter Hoehn (wassa@columbia.edu)
 */

public class Rule {

	private String description;
	private Target target;
	private static Logger log = Logger.getLogger(Rule.class.getName());

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
	 * Unmarshalls the <code>Rule</code> into an xml <code>Element</code>.
	 * @return the xml <code>Element</code>
	 */

	public Element unmarshall() {

		DOMParser parser = new DOMParser();
		Document placeHolder = parser.getDocument();
		Element ruleNode = placeHolder.createElement("Rule");

		if (description != null) {
			Element descriptionNode = placeHolder.createElement("Description");
			descriptionNode.appendChild(placeHolder.createTextNode(description));
			ruleNode.appendChild(descriptionNode);
		}

		return ruleNode;
	}

	/**
	 * Creates an ARP Rule from an xml representation.
	 * @param the xml <code>Element</code> containing the ARP Rule.
	 */

	public void marshall(Element element) throws ArpMarshallingException {

		//Make sure we are dealing with a Rule
		if (!element.getTagName().equals("Rule")) {
			log.error("Element data does not represent an ARP Rule.");
			throw new ArpMarshallingException("Element data does not represent an ARP Rule.");
		}

		//Grab the description
		NodeList descriptionNodes = element.getElementsByTagName("Description");
		if (descriptionNodes.getLength() > 0) {
			Element descriptionNode = (Element) descriptionNodes.item(0);
			if (descriptionNode.hasChildNodes()
				&& descriptionNode.getFirstChild().getNodeType() == Node.TEXT_NODE) {
				description = ((CharacterData) descriptionNode.getFirstChild()).getData();
			}
		}

		//Create the Target
		NodeList targetNodes = element.getElementsByTagName("Target");
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
	}

	/**
	 * Method matchesRequest.
	 * @param requester
	 * @param resource
	 * @return boolean
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

		void marshall(Element element) throws ArpMarshallingException {

			//Make sure we are deling with a Target
			if (!element.getTagName().equals("Target")) {
				log.error("Element data does not represent an ARP Rule Target.");
				throw new ArpMarshallingException("Element data does not represent an ARP Rule target.");
			}
			NodeList targetNodeList = element.getChildNodes();
			if (targetNodeList.getLength() < 1 || targetNodeList.getLength() > 2) {
				log.error("ARP Rule Target contains invalid data: incorrect number of elements");
				throw new ArpMarshallingException("ARP Rule Target contains invalid data: incorrect number of elements");
			}

			//Handle <AnyTarget/> definitions
			if (targetNodeList.getLength() == 1) {
				if (targetNodeList.item(0).getNodeType() == Node.ELEMENT_NODE
					&& ((Element) targetNodeList.item(0)).getTagName().equals("AnyTarget")) {
					matchesAny = true;
					return;
				}
				log.error("ARP Rule Target contains invalid data.");
				throw new ArpMarshallingException("ARP Rule Target contains invalid data.");
			}

			//Create Requester
			if (targetNodeList.item(0).getNodeType() == Node.ELEMENT_NODE
				&& ((Element) targetNodeList.item(0)).getTagName().equals("Requester")) {
				requester = new Requester();
				requester.marshall((Element) targetNodeList.item(0));
			} else {
				log.error("ARP Rule Target contains invalid data.");
				throw new ArpMarshallingException("ARP Rule Target contains invalid data.");
			}
			//Handle <AnyResource/>
			//Create Resource
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
		boolean matchesAny() {
			return matchesAny;
		}
		URI getMatchFunctionIdentifier() {
			return matchFunctionIdentifier;
		}
		String getValue() {
			return value;
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
		void marshall(Element element) throws ArpMarshallingException {
			//Make sure we are deling with a Requester
			if (!element.getTagName().equals("Requester")) {
				log.error("Element data does not represent an ARP Rule Target.");
				throw new ArpMarshallingException("Element data does not represent an ARP Rule target.");
			}
			if (element.hasChildNodes() && element.getFirstChild().getNodeType() == Node.TEXT_NODE) {
				value = ((CharacterData) element.getFirstChild()).getData();
			} else {
				log.error("Element data does not represent an ARP Rule Target.");
				throw new ArpMarshallingException("Element data does not represent an ARP Rule target.");
			}
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

}
