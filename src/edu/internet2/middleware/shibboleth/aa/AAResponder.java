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
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import javax.naming.CommunicationException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.apache.log4j.Logger;
import org.opensaml.SAMLAttribute;
import org.opensaml.SAMLException;

import edu.internet2.middleware.shibboleth.aa.arp.ArpAttribute;
import edu.internet2.middleware.shibboleth.aa.arp.ArpEngine;
import edu.internet2.middleware.shibboleth.aa.arp.ArpProcessingException;
import edu.internet2.middleware.shibboleth.aa.arp.provider.ShibArpAttribute;

public class AAResponder {

	protected ArpEngine arpEngine;
	protected DirContext ctx;
	protected String domain;
	private static Logger log = Logger.getLogger(AAResponder.class.getName());

	public AAResponder(ArpEngine arpEngine, DirContext ctx, String domain) throws AAException {

		this.arpEngine = arpEngine;
		this.ctx = ctx;
		this.domain = domain;
	}

	public SAMLAttribute[] getReleaseAttributes(
		Principal principal,
		String searchFilter,
		String requester,
		URL resource)
		throws AAException {

		DirContext userCtx = queryDataSource(principal, searchFilter);

		try {
			//optimization... find out which attributes to resolve
			URI[] potentialAttributes =
				arpEngine.listPossibleReleaseAttributes(principal, requester, resource);

			//resolve for each attribute
			Set arpAttributes = new HashSet();

			for (int i = 0; i < potentialAttributes.length; i++) {
				ShibArpAttribute arpAttribute = new ShibArpAttribute(potentialAttributes[i].toString());

				Attributes attrs =
					ctx.getAttributes(
						"",
						new String[] {
							 arpAttribute.getName().substring(arpAttribute.getName().lastIndexOf(":") + 1)});
				Attribute dAttr =
					attrs.get(arpAttribute.getName().substring(arpAttribute.getName().lastIndexOf(":") + 1));
				NamingEnumeration directoryValuesEnum = dAttr.getAll();
				List directoryValues = new ArrayList();
				while (directoryValuesEnum.hasMoreElements()) {
					directoryValues.add(directoryValuesEnum.next());
				}
				arpAttribute.setValues(directoryValues.toArray());
				arpAttributes.add(arpAttribute);
			}

			//filter and convert to SAML
			ArpAttribute[] filteredAttributes =
				arpEngine.filterAttributes(
					(ArpAttribute[]) arpAttributes.toArray(new ArpAttribute[0]),
					principal,
					requester,
					resource);

			Set samlAttributes = new HashSet();
			for (int i = 0; i < filteredAttributes.length; i++) {
				samlAttributes.add(toSaml(filteredAttributes[i], requester));
			}
			return (SAMLAttribute[]) samlAttributes.toArray(new SAMLAttribute[0]);

		} catch (NamingException e) {
			log.error(
				"An error occurred while retieving data for principal ("
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

	private DirContext queryDataSource(Principal principal, String searchFilter)
		throws AAException {
		try {
			try {
				return getUserContext(principal.getName(), searchFilter);
			} catch (CommunicationException ce) {
				synchronized (ctx) {
					log.debug(ce);
					log.warn(
						"Encountered a connection problem while querying for attributes.  Re-initializing JNDI context and retrying...");
					ctx = new InitialDirContext(ctx.getEnvironment());
				}
				return getUserContext(principal.getName(), searchFilter);
			}
		} catch (NamingException e) {
			log.error(
				"An error occurred while retieving data for principal ("
					+ principal.getName()
					+ ") :"
					+ e.getMessage());
			throw new AAException("Error retrieving data for principal.");
		}
	}

	private DirContext getUserContext(String userName, String searchFilter)
		throws CommunicationException, NamingException, AAException {

		DirContext userCtx = null;
		if (searchFilter == null) {
			searchFilter = "";
		}
		int indx = searchFilter.indexOf("%s");
		if (indx < 0) {
			try {
				userCtx = (DirContext) ctx.lookup(searchFilter + userName);
			} catch (NameNotFoundException nnfe) {
				log.error(
					"Could not locate a user ("
						+ userName
						+ ") as a result of searching with ("
						+ searchFilter
						+ ").");
				throw new AAException("No data available for this principal.");
			}
		} else {
			/* This is a search filter. Search after replacing %s with uid*/
			StringBuffer tmp = new StringBuffer(searchFilter);
			tmp.delete(indx, indx + 2);
			tmp.insert(indx, userName);
			searchFilter = tmp.toString();
			SearchControls ctls = new SearchControls();
			ctls.setReturningObjFlag(true);
			NamingEnumeration en = ctx.search("", searchFilter, ctls);
			if (!en.hasMore()) {
				log.error(
					"Could not locate a user ("
						+ userName
						+ ") as a result of searching with ("
						+ searchFilter
						+ ").");
				throw new AAException("No data available for this principal.");
			}
			userCtx = (DirContext) ((SearchResult) en.next()).getObject();
			if (en.hasMore()) {
				log.error(
					"Located multiple ("
						+ userName
						+ ") users as a result of searching with ("
						+ searchFilter
						+ ").");
				throw new AAException("Cannot disambiguate data for this principal.");
			}
		}
		return userCtx;
	}

	private SAMLAttribute toSaml(ArpAttribute attribute, String recipient)
		throws NamingException, AAException {

		if (attribute == null) {
			return null;
		}

		log.debug("Converting Attribute (" + attribute.getName() + ") to SAML.");

		try {
			Class attrClass =
				Class.forName(
					"edu.internet2.middleware.shibboleth.aaLocal.attributes."
						+ attribute.getName().substring(
							attribute.getName().lastIndexOf(":") + 1));
			log.debug("Loaded the class for " + attrClass);
			ShibAttribute sa = (ShibAttribute) attrClass.newInstance();
			return sa.toSamlAttribute(this.domain, attribute.getValues(), recipient);

		} catch (SAMLException e) {
			log.error(
				"Error converting attribute to SAML ("
					+ attribute.getName()
					+ ") :"
					+ e.getMessage());
			return null;
		} catch (Exception e) {
			log.error("Failed to load the class for attribute (" + attribute.getName() + ") :" + e);
			return null;
		}

	}
}
