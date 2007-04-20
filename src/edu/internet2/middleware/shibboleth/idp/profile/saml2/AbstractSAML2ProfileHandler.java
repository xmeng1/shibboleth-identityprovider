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

import java.util.List;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.IdentifierGenerator;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextDeclRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.Subject;
import org.opensaml.xml.XMLObjectBuilderFactory;

import edu.internet2.middleware.shibboleth.idp.profile.AbstractSAMLProfileHandler;

/**
 * Common implementation details for profile handlers.
 */
public abstract class AbstractSAML2ProfileHandler extends
		AbstractSAMLProfileHandler {

	/** SAML Version for this profile handler. */
	public static final SAMLVersion SAML_VERSION = SAMLVersion.VERSION_20;

	/** URI for the SAML 2 protocol. */
	public static final String SAML20_PROTOCOL_URI = "urn:oasis:names:tc:SAML:2.0:protocol";

	/** Class logger. */
	private static Logger log = Logger
			.getLogger(AbstractSAML2ProfileHandler.class);

	/** For building XML. */
	private XMLObjectBuilderFactory builderFactory;

	/** For generating random ids. */
	private IdentifierGenerator idGenerator;

	/** Builder for Response elements. */
	protected SAMLObjectBuilder<Response> responseBuilder;

	/** Builder for Status elements. */
	protected SAMLObjectBuilder<Status> statusBuilder;

	/** Builder for StatusCode elements. */
	protected SAMLObjectBuilder<StatusCode> statusCodeBuilder;

	/** Builder for StatusMessage elements. */
	protected SAMLObjectBuilder<StatusMessage> statusMessageBuilder;

	/** Builder for Issuer elements. */
	protected SAMLObjectBuilder<Issuer> issuerBuilder;

	/** Builder for Assertion elements. */
	protected SAMLObjectBuilder<Assertion> assertionBuilder;

	/** Builder for Condition elements. */
	protected SAMLObjectBuilder<Conditions> conditionsBuilder;

	/** Builder for AuthnStatement elements. */
	protected SAMLObjectBuilder<AuthnStatement> authnStatementBuilder;

	/** Builder for AuthnContext elements. */
	protected SAMLObjectBuilder<AuthnContext> authnContextBuilder;

	/** Builder for AuthnContextClassRef elements. */
	protected SAMLObjectBuilder<AuthnContextClassRef> authnContextClassRefBuilder;

	/** Builder for AuthnContextDeclRef elements. */
	protected SAMLObjectBuilder<AuthnContextDeclRef> authnContextDeclRefBuilder;

	/** Builder for AudienceRestriction conditions. */
	protected SAMLObjectBuilder<AudienceRestriction> audienceRestrictionBuilder;

	/** Builder for Audience elemenets. */
	protected SAMLObjectBuilder<Audience> audienceBuilder;

	/**
	 * Default constructor.
	 */
	public AbstractSAML2ProfileHandler() {
		builderFactory = Configuration.getBuilderFactory();
		idGenerator = new SecureRandomIdentifierGenerator();

		assertionBuilder = (SAMLObjectBuilder<Assertion>) getBuilderFactory()
				.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
		authnStatementBuilder = (SAMLObjectBuilder<AuthnStatement>) getBuilderFactory()
				.getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
		authnContextBuilder = (SAMLObjectBuilder<AuthnContext>) getBuilderFactory()
				.getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
		authnContextClassRefBuilder = (SAMLObjectBuilder<AuthnContextClassRef>) getBuilderFactory()
				.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
		authnContextDeclRefBuilder = (SAMLObjectBuilder<AuthnContextDeclRef>) getBuilderFactory()
				.getBuilder(AuthnContextDeclRef.DEFAULT_ELEMENT_NAME);
		audienceRestrictionBuilder = (SAMLObjectBuilder<AudienceRestriction>) getBuilderFactory()
				.getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME);
		audienceBuilder = (SAMLObjectBuilder<Audience>) getBuilderFactory()
				.getBuilder(Audience.DEFAULT_ELEMENT_NAME);
		conditionsBuilder = (SAMLObjectBuilder<Conditions>) getBuilderFactory()
				.getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
		responseBuilder = (SAMLObjectBuilder<Response>) builderFactory
				.getBuilder(Response.DEFAULT_ELEMENT_NAME);
		statusBuilder = (SAMLObjectBuilder<Status>) builderFactory
				.getBuilder(Status.DEFAULT_ELEMENT_NAME);
		statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) builderFactory
				.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
		statusMessageBuilder = (SAMLObjectBuilder<StatusMessage>) builderFactory
				.getBuilder(StatusMessage.DEFAULT_ELEMENT_NAME);
		issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
				.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
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
	public IdentifierGenerator getIdGenerator() {
		return idGenerator;
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

		Status status = statusBuilder.buildObject();
		StatusCode statusCode = statusCodeBuilder.buildObject();

		statusCode.setValue(topLevelCode);
		if (secondLevelCode != null) {
			StatusCode secondLevelStatusCode = statusCodeBuilder.buildObject();
			secondLevelStatusCode.setValue(secondLevelCode);
			statusCode.setStatusCode(secondLevelStatusCode);
		}

		if (secondLevelFailureMessage != null) {
			StatusMessage msg = statusMessageBuilder.buildObject();
			msg.setMessage(secondLevelFailureMessage);
			status.setStatusMessage(msg);
		}

		return status;
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
	 * 
	 * @return a Status object.
	 */
	protected Status buildStatus(String topLevelCode,
			final StatusCode secondLevelCode) {

		Status status = statusBuilder.buildObject();
		StatusCode statusCode = statusCodeBuilder.buildObject();

		statusCode.setValue(topLevelCode);
		if (secondLevelCode != null) {
			statusCode.setStatusCode(secondLevelCode);
		}

		return status;
	}

	/**
	 * Build a StatusCode.
	 * 
	 * @param statusCode
	 *            The URI status code.
	 * @param message
	 *            The message; may be <code>null</code.
	 *
	 * @return a StatusCode object.
	 */
	protected StatusCode buildStatusCode(String statusCode) {
		return null;
	}

	/**
	 * Build a SAML 2 Response element with basic fields populated.
	 * 
	 * Failure handlers can send the returned response element to the RP.
	 * Success handlers should add the assertions before sending it.
	 * 
	 * @param inResponseTo
	 *            The ID of the request this is in response to.
	 * @param issueInstant
	 *            The timestamp of this response.
	 * @param issuer
	 *            The URI of the RP issuing the response.
	 * @param status
	 *            The response's status code.
	 * 
	 * @return The populated Response object.
	 */
	protected Response buildResponse(String inResponseTo,
			final DateTime issueInstant, String issuer, final Status status) {

		Response response = responseBuilder.buildObject();

		Issuer i = issuerBuilder.buildObject();
		i.setValue(issuer);

		response.setVersion(SAML_VERSION);
		response.setID(getIdGenerator().generateIdentifier());
		response.setInResponseTo(inResponseTo);
		response.setIssueInstant(issueInstant);
		response.setIssuer(i);
		response.setStatus(status);

		return response;
	}

	/**
	 * Build a skeletal SAML 2 assertion.
	 * 
	 * Note, the caller may either set the audiences in the conditions argument,
	 * or pass a list of URIs to this method. If the latter option is chosen,
	 * this method will create the appropriate AudienceRestriction element.
	 * 
	 * @param subject
	 *            The Subject of the assertion.
	 * @param conditions
	 *            The conditions object.
	 * @param issuer
	 *            The URI of the RP issuing the assertion.
	 * @param audiences
	 *            A possibly null array of audience URIs for the assertion.
	 * 
	 * @return The assertion object.
	 */
	protected Assertion buildAssertion(final Subject subject,
			final Conditions conditions, final Issuer issuer,
			final String[] audiences) {

		Assertion assertion = assertionBuilder.buildObject();
		assertion.setID(getIdGenerator().generateIdentifier());
		assertion.setVersion(SAML_VERSION);
		assertion.setIssueInstant(new DateTime());
		assertion.setConditions(conditions);
		assertion.setSubject(subject);

		Issuer i = issuerBuilder.buildObject();
		i.setValue(issuer.getValue());
		assertion.setIssuer(i);

		// if audiences were specified, set an AudienceRestriction condition
		if (audiences != null && audiences.length > 0) {

			List<AudienceRestriction> audienceRestrictionConditions = assertion
					.getConditions().getAudienceRestrictions();

			AudienceRestriction audienceRestriction = audienceRestrictionBuilder
					.buildObject();
			audienceRestrictionConditions.add(audienceRestriction);

			List<Audience> audienceList = audienceRestriction.getAudiences();

			for (String audienceURI : audiences) {
				Audience audience = audienceBuilder.buildObject();
				audience.setAudienceURI(audienceURI);
				audienceList.add(audience);
			}
		}

		return assertion;
	}
}
