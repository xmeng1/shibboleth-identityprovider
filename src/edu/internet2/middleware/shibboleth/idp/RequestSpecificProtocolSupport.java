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

package edu.internet2.middleware.shibboleth.idp;

import java.net.URI;
import java.security.Principal;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

import org.apache.log4j.Logger;
import org.opensaml.InvalidCryptoException;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAttribute;
import org.opensaml.SAMLException;
import org.opensaml.SAMLResponse;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataFilter;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.security.TrustEngine;
import org.opensaml.security.X509EntityCredential;
import org.opensaml.xml.XMLObject;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.aa.AAAttribute;
import edu.internet2.middleware.shibboleth.aa.AAException;
import edu.internet2.middleware.shibboleth.aa.arp.ArpProcessingException;
import edu.internet2.middleware.shibboleth.artifact.ArtifactMapper;
import edu.internet2.middleware.shibboleth.common.RelyingParty;
import edu.internet2.middleware.shibboleth.common.RelyingPartyMapper;

/**
 * IdPProtocolSupport implementation that offers functionality that is specific to a particular request.
 * 
 * @author Walter Hoehn
 */
public class RequestSpecificProtocolSupport implements IdPProtocolSupport {

	IdPProtocolSupport wrapped;

	RequestSpecificProtocolSupport(GeneralProtocolSupport generalSupport, HttpServletRequest request,
			HttpServletResponse response) {

		wrapped = generalSupport;
	}

	public void addMetadataProvider(Element element) {

		wrapped.addMetadataProvider(element);
	}

	public void destroy() {

		wrapped.destroy();
	}

	public ArtifactMapper getArtifactMapper() {

		return wrapped.getArtifactMapper();
	}

	public IdPConfig getIdPConfig() {

		return wrapped.getIdPConfig();
	}

	public Collection<? extends SAMLAttribute> getReleaseAttributes(Principal principal, RelyingParty relyingParty,
			String requester) throws AAException {

		return wrapped.getReleaseAttributes(principal, relyingParty, requester);
	}

	public Collection<? extends SAMLAttribute> getReleaseAttributes(Principal principal, RelyingParty relyingParty,
			String requester, Collection<URI> attributeNames) throws AAException {

		return wrapped.getReleaseAttributes(principal, relyingParty, requester, attributeNames);
	}

	public RelyingPartyMapper getRelyingPartyMapper() {

		return wrapped.getRelyingPartyMapper();
	}

	public Logger getTransactionLog() {

		return wrapped.getTransactionLog();
	}

	public TrustEngine<X509Credential> getTrustEngine() {

		return wrapped.getTrustEngine();
	}

	public int providerCount() {

		return wrapped.providerCount();
	}

	public Collection<? extends SAMLAttribute> resolveAttributes(Principal principal, String requester,
			String responder, Map<String, AAAttribute> attributeSet) throws ArpProcessingException {

		return wrapped.resolveAttributes(principal, requester, responder, attributeSet);
	}

	public Collection<? extends SAMLAttribute> resolveAttributesNoPolicies(Principal principal, String requester,
			String responder, Map<String, AAAttribute> attributeSet) {

		return wrapped.resolveAttributesNoPolicies(principal, requester, responder, attributeSet);
	}

	public void signAssertions(SAMLAssertion[] assertions, RelyingParty relyingParty) throws InvalidCryptoException,
			SAMLException {

		wrapped.signAssertions(assertions, relyingParty);
	}

	public void signResponse(SAMLResponse response, RelyingParty relyingParty) throws SAMLException {

		wrapped.signResponse(response, relyingParty);
	}

	public EntitiesDescriptor getEntitiesDescriptor(String name) throws MetadataProviderException {

		return wrapped.getEntitiesDescriptor(name);
	}

	public EntityDescriptor getEntityDescriptor(String entityID) throws MetadataProviderException {

		return wrapped.getEntityDescriptor(entityID);
	}

	public XMLObject getMetadata() throws MetadataProviderException {

		return wrapped.getMetadata();
	}

	public MetadataFilter getMetadataFilter() {

		return wrapped.getMetadataFilter();
	}

	public List<RoleDescriptor> getRole(String entityID, QName roleName) throws MetadataProviderException {

		return wrapped.getRole(entityID, roleName);
	}

	public RoleDescriptor getRole(String entityID, QName roleName, String supportedProtocol)
			throws MetadataProviderException {

		return wrapped.getRole(entityID, roleName, supportedProtocol);
	}

	public boolean requireValidMetadata() {

		return wrapped.requireValidMetadata();
	}

	public void setMetadataFilter(MetadataFilter newFilter) throws MetadataProviderException {

		wrapped.setMetadataFilter(newFilter);
	}

	public void setRequireValidMetadata(boolean requireValidMetadata) {

		wrapped.setRequireValidMetadata(requireValidMetadata);
	}

}
