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

package edu.internet2.middleware.shibboleth.aa;

/**
 *  Attribute Authority & Release Policy
 *  Main logic that decides what to release 
 *
 * @author     Parviz Dousti (dousti@cmu.edu)
 * @author     Walter Hoehn (wassa@columbia.edu)
 */

import java.net.URI;
import java.net.URL;
import java.security.Principal;

import org.apache.log4j.Logger;
import org.opensaml.SAMLAttribute;
import org.opensaml.SAMLException;

import edu.internet2.middleware.shibboleth.aa.arp.ArpEngine;
import edu.internet2.middleware.shibboleth.aa.arp.ArpProcessingException;
import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver;

public class AAResponder {

	private ArpEngine arpEngine;
	private AttributeResolver resolver;
	private static Logger log = Logger.getLogger(AAResponder.class.getName());

	public AAResponder(ArpEngine arpEngine, AttributeResolver resolver) throws AAException {

		this.arpEngine = arpEngine;
		this.resolver = resolver;
	}

	public SAMLAttribute[] getReleaseAttributes(Principal principal, String requester, URL resource)
		throws AAException {

		try {
			URI[] potentialAttributes = arpEngine.listPossibleReleaseAttributes(principal, requester, resource);
			return getReleaseAttributes(principal, requester, resource, potentialAttributes);

		} catch (ArpProcessingException e) {
			log.error(
				"An error occurred while processing the ARPs for principal ("
					+ principal.getName()
					+ ") :"
					+ e.getMessage());
			throw new AAException("Error retrieving data for principal.");
		}
	}
	
	public SAMLAttribute[] getReleaseAttributes(
		Principal principal,
		String requester,
		URL resource,
		URI[] attributeNames)
		throws AAException {

		try {
			AAAttributeSet attributeSet = new AAAttributeSet();
			for (int i = 0; i < attributeNames.length; i++) {
				AAAttribute attribute = new AAAttribute(attributeNames[i].toString());
				attributeSet.add(attribute);
			}

			return resolveAttributes(principal, requester, resource, attributeSet);

		} catch (SAMLException e) {
			log.error(
				"An error occurred while creating attributes for principal ("
					+ principal.getName()
					+ ") :"
					+ e.getMessage());
			throw new AAException("Error retrieving data for principal.");

		} catch (ArpProcessingException e) {
			log.error(
				"An error occurred while processing the ARPs for principal ("
					+ principal.getName()
					+ ") :"
					+ e.getMessage());
			throw new AAException("Error retrieving data for principal.");
		}
	}

	private SAMLAttribute[] resolveAttributes(
		Principal principal,
		String requester,
		URL resource,
		AAAttributeSet attributeSet)
		throws ArpProcessingException {

		resolver.resolveAttributes(principal, requester, attributeSet);
		arpEngine.filterAttributes(attributeSet, principal, requester, resource);
		return attributeSet.getAttributes();
	}
}
