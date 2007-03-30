/*
 * Copyright [2007] [University Corporation for Advanced Internet Development, Inc.]
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

package edu.internet2.middleware.shibboleth.idp.profile.saml2;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.log4j.Logger;
import org.opensaml.Configuration;
import org.opensaml.common.IdentifierGenerator;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BindingException;
import org.opensaml.common.binding.MessageDecoder;
import org.opensaml.common.binding.MessageEncoder;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.encryption.Encrypter;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.xml.XMLObjectBuilderFactory;

import edu.internet2.middleware.shibboleth.common.attribute.filtering.FilteringEngine;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolver;
import edu.internet2.middleware.shibboleth.common.profile.ProfileHandler;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;

/**
 * Common implementation details for profile handlers.
 */
public abstract class AbstractProfileHandler implements ProfileHandler {

	/** SAML Version for this profile handler. */
	public static final SAMLVersion SAML_VERSION = SAMLVersion.VERSION_20;

	/** Class logger. */
	private static Logger log = Logger.getLogger(AbstractProfileHandler.class);

	/** For building XML. */
	private XMLObjectBuilderFactory builderFactory;

	/** For generating random ids. */
	private IdentifierGenerator idGenerator;

	/** For decoding requests. */
	private MessageDecoder<ServletRequest> decoder;

	/** For encoding responses. */
	private MessageEncoder<ServletResponse> encoder;

	/** For resolving attributes. */
	private AttributeResolver resolver;

	/** To determine releasable attributes. */
	private FilteringEngine engine;

	/** For encrypting XML. */
	private Encrypter encrypter;

	/** Builder for Response elements. */
	protected XMLObjectBuilder responseBuilder;

	/** Builder for Status elements. */
	private XMLObjectBuilder statusBuilder;

	/** Builder for StatusCode elements. */
	private XMLObjectBuilder statusCodeBuilder;

	/** Builder for StatusMessage elements. */
	private XMLObjectBuilder statusMessageBuilder;

	/** Builder for Issuer elements. */
	protected XMLObjectBuilder issuerBuilder;

	/**
	 * Default constructor.
	 */
	public AbstractProfileHandler() {
		builderFactory = Configuration.getBuilderFactory();
		idGenerator = new SecureRandomIdentifierGenerator();

		responseBuilder = builderFactory
				.getBuilder(Response.DEFAULT_ELEMENT_NAME);
		statusBuilder = builderFactory.getBuilder(Status.DEFAILT_ELEMENT_NAME);
		statusCodeBuilder = builderFactory
				.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
		statusMessageBuilder = builderFactory
				.getBuilder(StatusMessage.DEFAULT_ELEMENT_NAME);
		issuerBuilder = builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
	}

	/**
	 * Returns the XML builder factory.
	 * 
	 * @return Returns the builderFactory.
	 */
	public XMLObjectBuilderFactory getBuilderFactory() {
		return builderFactory;
	}

	/**
	 * Returns the id generator.
	 * 
	 * @return Returns the idGenerator.
	 */
	public SecureRandomIdentifierGenerator getIdGenerator() {
		return idGenerator;
	}

	/**
	 * Sets the decoder.
	 * 
	 * @param d
	 *            <code>MessageDecoder</code>
	 */
	public void setDecoder(MessageDecoder<ServletRequest> d) {
		decoder = d;
	}

	/**
	 * Returns the decoder.
	 * 
	 * @return <code>MessageDecoder</code>
	 */
	public MessageDecoder<ServletRequest> getDecoder() {
		return decoder;
	}

	/**
	 * Sets the encoder.
	 * 
	 * @param e
	 *            <code>MessageEncoder</code>
	 */
	public void setEncoder(MessageEncoder<ServletResponse> e) {
		encoder = e;
	}

	/**
	 * Returns the encoder.
	 * 
	 * @return <code>MessageEncoder</code>
	 */
	public MessageEncoder<ServletResponse> getEncoder() {
		return encoder;
	}

	/**
	 * Sets the attribute resolver.
	 * 
	 * @param r
	 *            <code>AttributeResolver</code>
	 */
	public void setAttributeResolver(AttributeResolver r) {
		resolver = r;
	}

	/**
	 * Returns the attribute resolver.
	 * 
	 * @return <code>AttributeResolver</code>
	 */
	public AttributeResolver getAttributeResolver() {
		return resolver;
	}

	/**
	 * Sets the filter engine.
	 * 
	 * @param e
	 *            <code>FilterEngine</code>
	 */
	public void setFilterEngine(FilteringEngine e) {
		engine = e;
	}

	/**
	 * Returns the filter engine.
	 * 
	 * @return <code>FilterEngine</code>
	 */
	public FilteringEngine getFilteringEngine() {
		return engine;
	}

	/**
	 * Sets the metadata provider.
	 * 
	 * @param p
	 *            <code>MetadataProvider</code>
	 */
	public void setMetadataProvider(MetadataProvider p) {
		provider = p;
	}

	/**
	 * Returns the metadata provider.
	 * 
	 * @return <code>MetadataProvider</code>
	 */
	public MetadataProvider getMetadataProvider() {
		return provider;
	}

	/**
	 * Returns the relying party configuration.
	 * 
	 * @return Returns the relyingParty.
	 */
	public RelyingPartyConfiguration getRelyingPartyConfiguration() {
		return relyingPartyConfiguration;
	}

	/**
	 * Sets the relying party configuration.
	 * 
	 * @param c
	 *            The relyingParty to set.
	 */
	public void setRelyingPartyConfiguration(RelyingPartyConfiguration c) {
		relyingPartyConfiguration = c;
	}

	/**
	 * Returns the encrypter.
	 * 
	 * @return Returns the encrypter.
	 */
	public Encrypter getEncrypter() {
		return encrypter;
	}

	/**
	 * Sets the encrypter.
	 * 
	 * @param e
	 *            The encrypter to set.
	 */
	public void setEncrypter(Encrypter e) {
		encrypter = e;
	}

	/**
	 * This decodes the attribute query message from the supplied request.
	 * 
	 * @param request
	 *            <code>ServletRequest</code>
	 * @return <code>SAMLObject</code>
	 * @throws BindingException
	 *             if the request cannot be decoded
	 */
	protected SAMLObject decodeMessage(ServletRequest request)
			throws BindingException {

		decoder.setRequest(request);
		decoder.decode();
		if (log.isDebugEnabled()) {
			log.debug("decoded servlet request");
		}

		return decoder.getSAMLMessage();
		;
	}

	/**
	 * This encodes the supplied response.
	 * 
	 * @param response
	 *            <code>SAMLObject</code>
	 * @throws BindingException
	 *             if the response cannot be encoded
	 */
	protected void encodeResponse(SAMLObject response) throws BindingException {

		encoder.setSAMLMessage(response);
		encoder.encode();
	}

	/**
	 * Build a status message, with an optional second-level failure message.
	 * 
	 * @param topLevelCode
	 *            The top-level status code. Should be from saml-core-2.0-os,
	 *            sec. 3.2.2.2
	 * @param secondLevelCode
	 *            An optional second-level failure code. Should be from
	 *            saml-core-2.0-is, sec 3.2.2.2. If null, no second-level Status
	 *            element will be set.
	 * @param secondLevelFailureMessage
	 *            An optional second-level failure message.
	 * 
	 * @return a Status object.
	 */
	protected Status buildStatus(String topLevelCode, String secondLevelCode,
			String secondLevelFailureMessage) {

		Status status = (Status) statusBuilder
				.buildObject(Status.DEFAULT_ELEMENT_NAME);
		StatusCode statusCode = (StatusCode) statusCodeBuilder
				.buildObject(StatusCode.DEFAULT_ELEMENT_NAME);

		statusCode.setValue(topLevelCode);
		if (secondLevelCode != null) {
			StatusCode secondLevelStatusCode = (StatusCode) statusCodeBuilder
					.buildObject(StatusCode.DEFAULT_ELEMENT_NAME);
			secondLevelStatusCode.setValue(secondLevelCode);
			statusCode.setStatusCode(secondLevelStatusCode);
		}

		if (secondLevelFailureMessage != null) {
			StatusMessage msg = (StatusMessage) statusMessageBuilder
					.buildObject(StatusMessage.DEFAULT_ELEMENT_NAME);
			msg.setMessage(secondLevelFailureMessage);
			status.setMessage(msg);
		}

		return status;
	}

	/**
	 * Build a SAML 2 Response element with basic fields populated.
	 * 
	 * Failure handlers can send the returned response element to the RP.
	 * Success handlers should add the assertions before sending it.
	 * 
	 * @param inResponseTo
	 *            The ID of the request this is in response to.
	 * @param issuer
	 *            The URI of the RP issuing the response.
	 * @param status
	 *            The response's status code.
	 * 
	 * @return The populated Response object.
	 */
	protected Response buildResponse(String inResponseTo, String issuer,
			final Status status) {

		Response response = (Response) responseBuilder
				.buildObject(Response.DEFAULT_ELEMENT_NAME);

		Issuer i = (Issuer) issuerBuilder
				.buildObject(Issuer.DEFAULT_ELEMENT_NAME);
		i.setValue(issuer);

		response.setVersion(SAML_VERSION);
		response.setId(getIdGenerator().generateIdentifier());
		response.setInResponseto(inResponseTo);
		response.setIssueInstance(new DateTime());
		response.setIssuer(i);
		response.setStatus(status);

		return response;
	}

	protected Assertion buildAssertion(final Subjcet subject,
			final Conditions conditions, String issuer, final String[] audiences) {

		Assertion assertion = (Assertion) assertionBuilder
				.buildObject(Assertion.DEFAULT_ELEMENT_NAME);
		assertion.setID(getIdGenerator().generateIdentifier());
		assertion.setVersion(SAML_VERSION);
		assertion.setIssueInstant(new DateTime());
		assertion.setConditions(conditions);
		assertion.setSubject(subject);

		Issuer i = (Issuer) issuerBuilder
				.buildObject(Issuer.DEFAULT_ELEMENT_NAME);
		i.setValue(issuer);
		assertion.setIssuer(i);

		// if audiences were specified, set an AudienceRestriction condition
		if (audiences != null && audiences.length > 0) {

			Conditions conditions = assertion.getConditions();
			List<AudienceRestriction> audienceRestrictionConditions = conditions
					.getAudienceRestrictions();

			for (String audienceURI : audiences) {

				Audience audience = (Audience) audienceBuilder
						.buildObject(Audience.DEFAULT_ELEMENT_NAME);
				audience.setAudienceURI(audienceURI);

				AudienceRestriction audienceRestriction = (AudienceRestriction) audienceRestrictionBuilder
						.buildObject(AudienceRestriction.DEFAULT_ELEMENT_NAME);
				List<Audience> audienceList = audienceRestriction
						.getAudiences();
				audienceList.add(audience);

				audienceRestrictionConditions.add(audienceRestriction);
			}
		}

		return assertion;
	}
}
