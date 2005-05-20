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

package edu.internet2.middleware.shibboleth.common;

import java.security.cert.X509Certificate;

import org.opensaml.SAMLSignedObject;

import edu.internet2.middleware.shibboleth.metadata.RoleDescriptor;

/**
 * Defines methodology for determing whether or not a system entity should trust the messages issued by another.
 * 
 * @author Walter Hoehn
 */
public interface Trust {

	/**
	 * Verifies that a certificate or ordered chain of certificates represents a valid credential set for a specific
	 * action by a specific entity.
	 * 
	 * @param certificateEE
	 *            the end-entity certificate being validated
	 * @param certificateChain
	 *            additional certificates supplied by the entity (may also contain the end-entity certificate)
	 * @param descriptor
	 *            the SAML 2 role descriptor of the entity purported to be performing the action
	 * @return true if the validation was successful and false if it was not successful
	 */
	public boolean validate(X509Certificate certificateEE, X509Certificate[] certificateChain, RoleDescriptor descriptor);

	/**
	 * Verifies that a certificate or ordered chain of certificates represents a valid credential set for a specific
	 * action by a specific entity.
	 * 
	 * @param certificateEE
	 *            the end-entity certificate being validated
	 * @param certificateChain
	 *            additional certificates supplied by the entity (may also contain the end-entity certificate)
	 * @param descriptor
	 *            the SAML 2 role descriptor of the entity purported to be performing the action
	 * @param checkName
	 *            whether the check the name of the certificate during the validation process, normally true unless the
	 *            name has already been checked as part of other processing (for example, TLS)
	 * @return true if the validation was successful and false if it was not successful
	 */
	public boolean validate(X509Certificate certificateEE, X509Certificate[] certificateChain,
			RoleDescriptor descriptor, boolean checkName);

	/**
	 * Verifies that a certificate or ordered chain of certificates represents a valid credential set for a specific
	 * action by a specific entity.
	 * 
	 * @param token
	 *            the signed object to validate
	 * @param descriptor
	 *            the SAML 2 role descriptor of the entity purported to be performing the action
	 * @return true if the validation was successful and false if it was not successful
	 */
	public boolean validate(SAMLSignedObject token, RoleDescriptor descriptor);
}