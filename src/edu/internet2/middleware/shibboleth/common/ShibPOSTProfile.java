/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation
 * for Advanced Internet Development, Inc. All rights reserved
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
 * <http://www.ucaid.edu> Internet2 Project. Alternately, this acknowledegement
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
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.common;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Vector;

import org.apache.log4j.Logger;
import org.apache.log4j.NDC;
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.InvalidAssertionException;
import org.opensaml.InvalidCryptoException;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAuthenticationStatement;
import org.opensaml.SAMLException;
import org.opensaml.SAMLNameIdentifier;
import org.opensaml.SAMLPOSTProfile;
import org.opensaml.SAMLResponse;
import org.opensaml.SAMLSignedObject;
import org.opensaml.SAMLStatement;
import org.opensaml.SAMLSubject;
import org.opensaml.TrustException;
import org.w3c.dom.Document;

/**
 * Basic Shibboleth POST browser profile implementation with basic support for
 * signing
 * 
 * @author Scott Cantor @created April 11, 2002
 */
public class ShibPOSTProfile {
	/** XML Signature algorithm to apply */
	protected String algorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;

	/** Policy URIs to attach or check against */
	protected ArrayList policies = new ArrayList();

	/** Official name of issuing site */
	protected String issuer = null;

	/** The URL of the receiving SHIRE */
	protected String receiver = null;

	/** Seconds allowed to elapse from issuance of response */
	protected int ttlSeconds = 0;

	private static Logger log = Logger.getLogger(ShibPOSTProfile.class.getName());

	/**
	 * SHIRE-side constructor for a ShibPOSTProfile object
	 * 
	 * @param policies
	 *            Set of policy URIs that the implementation must support
	 * @param receiver
	 *            URL of SHIRE
	 * @param ttlSeconds
	 *            Length of time in seconds allowed to elapse from issuance of
	 *            SAML response
	 * @exception SAMLException
	 *                Raised if a profile implementation cannot be constructed
	 *                from the supplied information
	 */
	public ShibPOSTProfile(Collection policies, String receiver, int ttlSeconds) throws SAMLException {
		if (policies == null || policies.size() == 0 || receiver == null || receiver.length() == 0 || ttlSeconds <= 0)
			throw new SAMLException(SAMLException.REQUESTER, "ShibPOSTProfile() found a null or invalid argument");

		this.receiver = receiver;
		this.ttlSeconds = ttlSeconds;
		this.policies.addAll(policies);
	}
	/**
	 * HS-side constructor for a ShibPOSTProfile object.
	 *  
	 */
	public ShibPOSTProfile() {
	}

	/**
	 * Locates an assertion containing a "bearer" AuthenticationStatement in
	 * the response and validates the enclosing assertion with respect to the
	 * POST profile
	 * 
	 * @param r
	 *            The response to the accepting site
	 * @return An SSO assertion
	 * 
	 * @throws SAMLException
	 *             Thrown if an SSO assertion can't be found
	 */
	public SAMLAssertion getSSOAssertion(SAMLResponse r) throws SAMLException {
		return SAMLPOSTProfile.getSSOAssertion(r, policies);
	}

	/**
	 * Locates a "bearer" AuthenticationStatement in the assertion and
	 * validates the statement with respect to the POST profile
	 * 
	 * @param a
	 *            The SSO assertion sent to the accepting site
	 * @return A "bearer" authentication statement
	 * 
	 * @throws SAMLException
	 *             Thrown if an SSO statement can't be found
	 */
	public SAMLAuthenticationStatement getSSOStatement(SAMLAssertion a) throws SAMLException {
		return SAMLPOSTProfile.getSSOStatement(a);
	}

	/**
	 * Examines a response to determine the source site name
	 * 
	 * @param r
	 * @return
	 */
	String getOriginSite(SAMLResponse r) {
		Iterator ia = r.getAssertions();
		while (ia.hasNext()) {
			Iterator is = ((SAMLAssertion) ia.next()).getStatements();
			while (is.hasNext()) {
				SAMLStatement s = (SAMLStatement) is.next();
				if (s instanceof SAMLAuthenticationStatement)
					return ((SAMLAuthenticationStatement) s).getSubject().getName().getName();
			}
		}
		return null;
	}

	/**
	 * Parse a Base-64 encoded buffer back into a SAML response and test its
	 * validity against the POST profile, including use of the default replay
	 * cache
	 * <P>
	 * 
	 * Also does trust evaluation based on the information available from the
	 * origin site mapper, in accordance with general Shibboleth processing
	 * semantics. Club-specific processing must be performed in a subclass.
	 * <P>
	 * 
	 * @param buf
	 *            A Base-64 encoded buffer containing a SAML response
	 * @param originSite
	 * @return SAML response sent by origin site
	 * @exception SAMLException
	 *                Thrown if the response cannot be understood or accepted
	 */
	public SAMLResponse accept(byte[] buf, StringBuffer originSite) throws SAMLException {
		// The built-in SAML functionality will do most of the basic non-crypto
		// checks.
		// Note that if the response only contains a status error, it gets
		// tossed out
		// as an exception.
		SAMLResponse r = SAMLPOSTProfile.accept(buf, receiver, ttlSeconds, false);

		if (originSite == null)
			originSite = new StringBuffer();

		// Now we do some more non-crypto (ie. cheap) work to match up the
		// origin site
		// with its associated data. If we can't even find a SSO statement in
		// the response
		// we just return the response to the caller, who will presumably
		// notice this.
		SAMLAssertion assertion = null;
		SAMLAuthenticationStatement sso = null;

		try {
			assertion = getSSOAssertion(r);
			sso = getSSOStatement(assertion);
		} catch (SAMLException e) {
			originSite.setLength(0);
			originSite.append(getOriginSite(r));
			throw e;
		}

		// Examine the subject information.
		SAMLSubject subject = sso.getSubject();
		if (subject.getName().getName() == null)
			throw new InvalidAssertionException(
				SAMLException.RESPONDER,
				"ShibPOSTProfile.accept() requires subject name qualifier");

		originSite.setLength(0);
		originSite.append(subject.getName().getName());
		String handleService = assertion.getIssuer();

		// Is this a trusted HS?
		OriginSiteMapper mapper = Init.getMapper();
		Iterator hsNames = mapper.getHandleServiceNames(originSite.toString());
		boolean bFound = false;
		while (!bFound && hsNames.hasNext())
			if (hsNames.next().equals(handleService))
				bFound = true;
		if (!bFound)
			throw new TrustException(
				SAMLException.RESPONDER,
				"ShibPOSTProfile.accept() detected an untrusted HS for the origin site");

		Key hsKey = mapper.getHandleServiceKey(handleService);
		KeyStore ks = mapper.getTrustedRoots();

		// Signature verification now takes place. We check the assertion and
		// the response.
		// Assertion signing is optional, response signing is mandatory.
		try {
			NDC.push("accept");
			if (assertion.isSigned()) {
				log.info("verifying assertion signature");
				verifySignature(assertion, handleService, ks, hsKey);
			}
			log.info("verifying response signature");
			verifySignature(r, handleService, ks, hsKey);
		} finally {
			NDC.pop();
		}
		return r;
	}

	/**
	 * Used by HS to generate a signed SAML response conforming to the POST
	 * profile
	 * <P>
	 * 
	 * @param recipient
	 *            URL of the assertion consumer
	 * @param relyingParty
	 *            the intended recipient of the response
	 * @param nameId
	 *            Name Identifier for the response
	 * @param subjectIP
	 *            Client address of subject (optional)
	 * @param authMethod
	 *            URI of authentication method being asserted
	 * @param authInstant
	 *            Date and time of authentication being asserted
	 * @param bindings
	 *            Set of SAML authorities the relying party may contact
	 *            (optional)
	 * @return SAML response to send to accepting site
	 * @exception SAMLException
	 *                Base class of exceptions that may be thrown during
	 *                processing
	 */
	public SAMLResponse prepare(
		String recipient,
		RelyingParty relyingParty,
		SAMLNameIdentifier nameId,
		String subjectIP,
		String authMethod,
		Date authInstant,
		Collection bindings)
		throws SAMLException {

		if (relyingParty.getIdentityProvider().getResponseSigningCredential() == null
			|| relyingParty.getIdentityProvider().getResponseSigningCredential().getPrivateKey() == null) {
			throw new InvalidCryptoException(
				SAMLException.RESPONDER,
				"ShibPOSTProfile.prepare() requires a response key.");
		}

		String responseAlgorithm;
		if (relyingParty.getIdentityProvider().getResponseSigningCredential().getCredentialType() == Credential.RSA) {
			responseAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;
		} else if (
			relyingParty.getIdentityProvider().getResponseSigningCredential().getCredentialType() == Credential.DSA) {
			responseAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_DSA;
		} else {
			throw new InvalidCryptoException(
				SAMLException.RESPONDER,
				"ShibPOSTProfile.prepare() currently only supports signing with RSA and DSA keys.");
		}

		Document doc = org.opensaml.XML.parserPool.newDocument();

		ArrayList audiences = new ArrayList();
		audiences.add(relyingParty.getProviderId());
		if (!relyingParty.getProviderId().equals(relyingParty.getName()))
			audiences.add(relyingParty.getName());

		String issuer;
		if (relyingParty.isLegacyProvider()) {
			//TODO must resolve this
			issuer = "fooIssuer";
		} else {
			issuer = relyingParty.getProviderId();
		}

		SAMLResponse r =
			SAMLPOSTProfile.prepare(recipient, issuer, audiences, nameId, subjectIP, authMethod, authInstant, bindings);
		r.toDOM(doc);

		if (relyingParty.getIdentityProvider().getAssertionSigningCredential() != null
			&& relyingParty.getIdentityProvider().getAssertionSigningCredential().getPrivateKey() != null) {

			String assertionAlgorithm;
			if (relyingParty.getIdentityProvider().getAssertionSigningCredential().getCredentialType()
				== Credential.RSA) {
				assertionAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;
			} else if (
				relyingParty.getIdentityProvider().getAssertionSigningCredential().getCredentialType()
					== Credential.DSA) {
				assertionAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_DSA;
			} else {
				throw new InvalidCryptoException(
					SAMLException.RESPONDER,
					"ShibPOSTProfile.prepare() currently only supports signing with RSA and DSA keys.");
			}

			((SAMLAssertion) r.getAssertions().next()).sign(
				assertionAlgorithm,
				relyingParty.getIdentityProvider().getAssertionSigningCredential().getPrivateKey(),
				Arrays.asList(
					relyingParty.getIdentityProvider().getAssertionSigningCredential().getX509CertificateChain()));
		}

		r.sign(
			responseAlgorithm,
			relyingParty.getIdentityProvider().getResponseSigningCredential().getPrivateKey(),
			Arrays.asList(relyingParty.getIdentityProvider().getResponseSigningCredential().getX509CertificateChain()));

		return r;
	}

	/**
	 * Searches the replay cache for the specified assertion and inserts a
	 * newly seen assertion into the cache
	 * <P>
	 * 
	 * Also performs garbage collection of the cache by deleting expired
	 * entries.
	 * 
	 * @param a
	 *            The assertion to check
	 * @return true iff the assertion has not been seen before
	 */
	public synchronized boolean checkReplayCache(SAMLAssertion a) {
		// Default implementation uses the basic replay cache implementation.
		return SAMLPOSTProfile.checkReplayCache(a);
	}

	/**
	 * Default signature verification algorithm uses an embedded X509
	 * certificate(s) or an explicit key to verify the signature. The
	 * certificate is examined to insure the subject CN matches the signer, and
	 * that it is signed by a trusted CA
	 * 
	 * @param obj
	 *            The object containing the signature
	 * @param signerName
	 *            The name of the signer
	 * @param ks
	 *            A keystore containing trusted root certificates
	 * @param knownKey
	 *            An explicit key to use if a certificate cannot be found
	 * @param simple
	 *            Verify according to simple SAML signature profile?
	 * 
	 * @throws SAMLException
	 *             Thrown if the signature cannot be verified
	 */
	protected void verifySignature(SAMLSignedObject obj, String signerName, KeyStore ks, Key knownKey)
		throws SAMLException {
		try {
			NDC.push("verifySignature");

			if (!obj.isSigned()) {
				log.error("unable to find a signature");
				throw new TrustException(
					SAMLException.RESPONDER,
					"ShibPOSTProfile.verifySignature() given an unsigned object");
			}

			if (knownKey != null) {
				log.info("verifying signature with known key value, ignoring signature KeyInfo");
				obj.verify(knownKey);
				return;
			}

			log.info("verifying signature with embedded KeyInfo");
			obj.verify();

			// This is pretty painful, and this is leveraging the supposedly
			// automatic support in JDK 1.4.
			// First we have to extract the certificates from the object.
			Iterator certs_from_obj = obj.getX509Certificates();
			if (!certs_from_obj.hasNext()) {
				log.error("need certificates inside object to establish trust");
				throw new TrustException(
					SAMLException.RESPONDER,
					"ShibPOSTProfile.verifySignature() can't find any certificates");
			}

			// We assume the first one in the set is the end entity cert.
			X509Certificate entity_cert = (X509Certificate) certs_from_obj.next();

			// Match the CN of the entity cert with the expected signer.
			String dname = entity_cert.getSubjectDN().getName();
			log.debug("found entity cert with DN: " + dname);
			String cname = "CN=" + signerName;
			if (!dname.equalsIgnoreCase(cname) && !dname.regionMatches(true, 0, cname + ',', 0, cname.length() + 1)) {
				log.error(
					"verifySignature() found a mismatch between the entity certificate's DN and the expected signer: "
						+ signerName);
				throw new TrustException(
					SAMLException.RESPONDER,
					"ShibPOSTProfile.verifySignature() found mismatch between entity certificate and expected signer");
			}

			// Prep a chain between the entity cert and the trusted roots.
			X509CertSelector targetConstraints = new X509CertSelector();
			targetConstraints.setCertificate(entity_cert);
			PKIXBuilderParameters params = new PKIXBuilderParameters(ks, targetConstraints);
			params.setMaxPathLength(-1);

			Vector certbag = new Vector();
			certbag.add(entity_cert);
			while (certs_from_obj.hasNext())
				certbag.add(certs_from_obj.next());
			CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(certbag);
			CertStore store = CertStore.getInstance("Collection", ccsp);
			params.addCertStore(store);

			// Attempt to build a path.
			CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX");
			PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) cpb.build(params);
		} catch (CertPathBuilderException e) {
			log.error("caught a cert path builder exception: " + e.getMessage());
			throw new TrustException(
				SAMLException.RESPONDER,
				"ShibPOSTProfile.verifySignature() unable to build a PKIX certificate path",
				e);
		} catch (GeneralSecurityException e) {
			log.error("caught a general security exception: " + e.getMessage());
			throw new TrustException(
				SAMLException.RESPONDER,
				"ShibPOSTProfile.verifySignature() unable to build a PKIX certificate path",
				e);
		} finally {
			NDC.pop();
		}
	}
}
