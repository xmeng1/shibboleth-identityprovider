/*
 * Copyright [2006] [University Corporation for Advanced Internet Development, Inc.]
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

package edu.internet2.middleware.shibboleth.idp.authn;

import java.util.List;
import java.util.LinkedList;

import org.apache.log4j.Logger;

import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextDeclRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.RequestedAuthnContext;

/**
 * A SAML 2.0 {@link LoginContext}.
 * 
 * This class can interpret {@link RequestedAuthnContext} and act accordingly.
 */
public class Saml2LoginContext extends LoginContext {

	private static final Logger log = Logger.getLogger(Saml2LoginContext.class);

	/** The {@link RequestedAuthnContext} */
	private RequestedAuthnContext ctx;

	/**
	 * Creates a new instance of Saml2LoginContext.
	 * 
	 * @param authnRequest
	 *            A SAML 2.0 Authentication Request.
	 */
	public Saml2LoginContext(AuthnRequest authnRequest) {

		if (authnRequest != null) {
			forceAuth = authnRequest.isForceAuthn();
			passiveAuth = authnRequest.isPassive();
			ctx = authnRequest.getRequestedAuthnContext();
		}
	}

	/**
	 * This method evaluates a SAML2 {@link RequestedAuthnContext} and returns
	 * the list of requested authentication method URIs.
	 * 
	 * If the AuthnQuery did not contain a RequestedAuthnContext, this method
	 * will return <code>null</code>.
	 * 
	 * @return An array of authentication method URIs, or <code>null</code>.
	 */
	public String[] getRequestedAuthenticationMethods() {

		if (ctx == null)
			return null;

		// For the immediate future, we only support the "exact" comparator.
		// XXX: we should probably throw an exception or somehow indicate this
		// as an error to the caller.
		AuthnContextComparisonTypeEnumeration comparator = ctx.getComparison();
		if (comparator != null
				&& comparator != AuthnContextComparisonTypeEnumeration.EXACT) {
			log
					.error("Unsupported comparision operator ( "
							+ comparator
							+ ") in RequestedAuthnContext. Only exact comparisions are supported.");
			return null;
		}

		// build a list of all requested authn classes and declrefs
		List<String> requestedAuthnMethods = new LinkedList<String>();
		List<AuthnContextClassRef> authnClasses = ctx
				.getAuthnContextClassRefs();
		List<AuthnContextDeclRef> authnDeclRefs = ctx.getAuthnContextDeclRefs();

		if (authnClasses != null) {
			for (AuthnContextClassRef classRef : authnClasses) {
				if (classRef != null) {
					String s = classRef.getAuthnContextClassRef();
					if (s != null) {
						requestedAuthnMethods.add(s);
					}
				}
			}
		}

		if (authnDeclRefs != null) {
			for (AuthnContextDeclRef declRef : authnDeclRefs) {
				if (declRef != null) {
					String s = declRef.getAuthnContextDeclRef();
					if (s != null) {
						requestedAuthnMethods.add(s);
					}
				}
			}
		}

		if (requestedAuthnMethods.size() == 0) {
			return null;
		} else {
			String[] methods = new String[requestedAuthnMethods.size()];
			return requestedAuthnMethods.toArray(methods);
		}

	}
}
