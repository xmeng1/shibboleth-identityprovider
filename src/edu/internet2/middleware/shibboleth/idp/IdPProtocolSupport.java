/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.] Licensed under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in
 * writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.idp;

import java.net.URI;
import java.security.Principal;
import java.util.Collection;
import java.util.Map;

import org.apache.log4j.Logger;
import org.opensaml.InvalidCryptoException;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAttribute;
import org.opensaml.SAMLException;
import org.opensaml.SAMLResponse;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.security.TrustEngine;
import org.opensaml.security.X509EntityCredential;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.aa.AAAttribute;
import edu.internet2.middleware.shibboleth.aa.AAException;
import edu.internet2.middleware.shibboleth.aa.arp.ArpProcessingException;
import edu.internet2.middleware.shibboleth.artifact.ArtifactMapper;
import edu.internet2.middleware.shibboleth.common.RelyingParty;
import edu.internet2.middleware.shibboleth.common.RelyingPartyMapper;

/**
 * Delivers core IdP functionality (Attribute resolution, ARP filtering, Metadata lookup, Signing, Mapping between local &
 * SAML identifiers, etc.) to components that process protocol-specific requests.
 * 
 * @author Walter Hoehn
 */
public interface IdPProtocolSupport extends MetadataProvider {

	/**
	 * Facility for logging transaction information. Should be used by most Protocol Hanlder implementations.
	 */
	public Logger getTransactionLog();

	/**
	 * Access to system-wide configuration.
	 */
	public IdPConfig getIdPConfig();

	/**
	 * Access to relying party-specific configuration.
	 */
	public RelyingPartyMapper getRelyingPartyMapper();

	public void signAssertions(SAMLAssertion[] assertions, RelyingParty relyingParty) throws InvalidCryptoException,
			SAMLException;

	public void signResponse(SAMLResponse response, RelyingParty relyingParty) throws SAMLException;

	/**
	 * Registered a metadata provider based on supplied XML configuration.
	 */
	public void addMetadataProvider(Element element);

	public Collection<? extends SAMLAttribute> getReleaseAttributes(Principal principal, RelyingParty relyingParty,
			String requester) throws AAException;

	public Collection<? extends SAMLAttribute> getReleaseAttributes(Principal principal, RelyingParty relyingParty,
			String requester, Collection<URI> attributeNames) throws AAException;

	public Collection<? extends SAMLAttribute> resolveAttributes(Principal principal, String requester,
			String responder, Map<String, AAAttribute> attributeSet) throws ArpProcessingException;

	public Collection<? extends SAMLAttribute> resolveAttributesNoPolicies(Principal principal, String requester,
			String responder, Map<String, AAAttribute> attributeSet);

	/**
	 * Cleanup resources that won't be released when this object is garbage-collected
	 */
	public void destroy();

	public ArtifactMapper getArtifactMapper();

	/**
	 * Returns an OpenSAML2 Trust Engine implementation.
	 */
	public TrustEngine<X509EntityCredential> getTrustEngine();

	/**
	 * Returns the number of active Metadata Providers.
	 */
	public int providerCount();

}