/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met: Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the
 * above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution, if any, must include the following acknowledgment: "This product includes
 * software developed by the University Corporation for Advanced Internet Development <http://www.ucaid.edu> Internet2
 * Project. Alternately, this acknowledegement may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear. Neither the name of Shibboleth nor the names of its contributors, nor Internet2,
 * nor the University Corporation for Advanced Internet Development, Inc., nor UCAID may be used to endorse or promote
 * products derived from this software without specific prior written permission. For written permission, please
 * contact shibboleth@shibboleth.org Products derived from this software may not be called Shibboleth, Internet2,
 * UCAID, or the University Corporation for Advanced Internet Development, nor may Shibboleth appear in their name,
 * without prior written permission of the University Corporation for Advanced Internet Development. THIS SOFTWARE IS
 * PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND
 * NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS
 * WITH LICENSEE. IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY CORPORATION FOR ADVANCED
 * INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.apache.log4j.NDC;
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.InvalidCryptoException;
import org.opensaml.NoSuchProviderException;
import org.opensaml.ReplayCache;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAudienceRestrictionCondition;
import org.opensaml.SAMLAuthenticationStatement;
import org.opensaml.SAMLBrowserProfile;
import org.opensaml.SAMLBrowserProfileFactory;
import org.opensaml.SAMLConfig;
import org.opensaml.SAMLException;
import org.opensaml.SAMLNameIdentifier;
import org.opensaml.SAMLResponse;
import org.opensaml.SAMLSignedObject;
import org.opensaml.SAMLSubject;
import org.opensaml.TrustException;
import org.w3c.dom.Document;

import edu.internet2.middleware.shibboleth.metadata.EntityDescriptor;
import edu.internet2.middleware.shibboleth.metadata.IDPProviderRole;
import edu.internet2.middleware.shibboleth.metadata.MetadataException;
import edu.internet2.middleware.shibboleth.metadata.ProviderRole;
import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderConfig;
import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderContext;
import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderConfig.ApplicationInfo;

// TODO: Do the cert extraction methods belong here? Probably not...

// TODO: Suggest we implement a separation layer between the SP config pieces and the input needed
// for this class. As long as metadata/etc. are shared, this should work.

/**
 * Basic Shibboleth POST browser profile implementation with basic support for signing
 * 
 * @author Scott Cantor @created April 11, 2002
 */
public class ShibBrowserProfile implements SAMLBrowserProfile {

	private static Pattern	regex		= Pattern.compile(".*?CN=([^,/]+).*");

	/** XML Signature algorithm to apply */
	protected String		algorithm	= XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;

	private static Logger	log			= Logger.getLogger(ShibBrowserProfile.class.getName());

    /** Policy URIs to attach or check against */
    protected ArrayList     policies    = new ArrayList();

    protected SAMLBrowserProfile profile = SAMLBrowserProfileFactory.getInstance(); 
    private static ServiceProviderContext context = ServiceProviderContext.getInstance();

    /*
     * The C++ class is constructed by passing enumerations of Metadata
     * providers, trust providers, etc from the <Application>. However,
     * those providers can change dynamically. This version only keeps
     * the applicationId that can be used to fetch the ApplicationInfo 
     * object and, from it, get the collections of provider plugins.
     * 
     * TODO: The reason they were still dynamic in C++ was that this wrapper
     * object was built dynamically. It's now contained within the application
     * interface itself and so it's "scoped" within the application and shares
     * the set of plugins from it. One reloads, the other is rebuilt.
     */
    private String applicationId = null;
    
    /**
     * Identify the <Application> from which to get plugins.
     * 
     * @param applicationId 
     */
    public ShibBrowserProfile(String applicationId) throws NoSuchProviderException {
        this.applicationId = applicationId;
    }

	/**
	 * Used by HS to generate a signed SAML response conforming to the POST profile
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
	 *            Set of SAML authorities the relying party may contact (optional)
	 * @return SAML response to send to accepting site
	 * @exception SAMLException
	 *                Base class of exceptions that may be thrown during processing
	 */
	public SAMLResponse prepare(String recipient, RelyingParty relyingParty, SAMLNameIdentifier nameId,
			String subjectIP, String authMethod, Date authInstant, Collection bindings) throws SAMLException {

		Document doc = org.opensaml.XML.parserPool.newDocument();

		ArrayList audiences = new ArrayList();
		if (relyingParty.getProviderId() != null) {
			audiences.add(relyingParty.getProviderId());
		}
		if (relyingParty.getName() != null && !relyingParty.getName().equals(relyingParty.getProviderId())) {
			audiences.add(relyingParty.getName());
		}

		String issuer = null;
		if (relyingParty.isLegacyProvider()) {
			
			log.debug("Service Provider is running Shibboleth <= 1.1.  Using old style issuer.");
			if (relyingParty.getIdentityProvider().getAuthNResponseSigningCredential() == null
					|| relyingParty.getIdentityProvider().getAuthNResponseSigningCredential().getX509Certificate() == null) {
				throw new SAMLException("Cannot serve legacy style assertions without an X509 certificate");
			}
			issuer = getHostNameFromDN(relyingParty.getIdentityProvider().getAuthNResponseSigningCredential()
					.getX509Certificate().getSubjectX500Principal());
			if (issuer == null || issuer.equals("")) {
				throw new SAMLException("Error parsing certificate DN while determining legacy issuer name.");
			}

		} else {
			issuer = relyingParty.getIdentityProvider().getProviderId();
		}

        // XXX: Inlined the old prepare method, this whole method should probably be pulled out into the IdP package.
        // At a minimum, artifact should be integrated in.
        SAMLResponse r = new SAMLResponse(
                null,
                recipient,
                Collections.singleton(
                        new SAMLAssertion(
                                issuer,
                                new Date(),
                                new Date(System.currentTimeMillis() + 1000 * SAMLConfig.instance().getIntProperty("org.opensaml.clock-skew")),
                                Collections.singleton(
                                        new SAMLAudienceRestrictionCondition(audiences)
                                        ),
                                null,
                                Collections.singleton(
                                        new SAMLAuthenticationStatement(
                                                new SAMLSubject(
                                                        nameId,
                                                        Collections.singleton(SAMLSubject.CONF_BEARER),
                                                        null,
                                                        null
                                                        ),
                                                authMethod,
                                                authInstant,
                                                subjectIP,
                                                null,
                                                bindings
                                                )
                                        )
                                )
                        ),
                null
                );
		r.toDOM(doc);

		//Sign the assertions, if appropriate
		if (relyingParty.getIdentityProvider().getAuthNAssertionSigningCredential() != null
				&& relyingParty.getIdentityProvider().getAuthNAssertionSigningCredential().getPrivateKey() != null) {

			String assertionAlgorithm;
			if (relyingParty.getIdentityProvider().getAuthNAssertionSigningCredential().getCredentialType() == Credential.RSA) {
				assertionAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;
			} else if (relyingParty.getIdentityProvider().getAuthNAssertionSigningCredential().getCredentialType() == Credential.DSA) {
				assertionAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_DSA;
			} else {
				throw new InvalidCryptoException(SAMLException.RESPONDER,
						"ShibPOSTProfile.prepare() currently only supports signing with RSA and DSA keys.");
			}

			((SAMLAssertion) r.getAssertions().next()).sign(assertionAlgorithm, relyingParty.getIdentityProvider()
					.getAuthNAssertionSigningCredential().getPrivateKey(), Arrays.asList(relyingParty.getIdentityProvider()
					.getAuthNAssertionSigningCredential().getX509CertificateChain()));
		}

		//Sign the response, if appropriate
		if (relyingParty.getIdentityProvider().getAuthNResponseSigningCredential() != null
				&& relyingParty.getIdentityProvider().getAuthNResponseSigningCredential().getPrivateKey() != null) {

			String responseAlgorithm;
			if (relyingParty.getIdentityProvider().getAuthNResponseSigningCredential().getCredentialType() == Credential.RSA) {
				responseAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;
			} else if (relyingParty.getIdentityProvider().getAuthNResponseSigningCredential().getCredentialType() == Credential.DSA) {
				responseAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_DSA;
			} else {
				throw new InvalidCryptoException(SAMLException.RESPONDER,
						"ShibPOSTProfile.prepare() currently only supports signing with RSA and DSA keys.");
			}

			r.sign(responseAlgorithm,
					relyingParty.getIdentityProvider().getAuthNResponseSigningCredential().getPrivateKey(), Arrays
							.asList(relyingParty.getIdentityProvider().getAuthNResponseSigningCredential()
									.getX509CertificateChain()));
		}

		return r;
	}

    /**
     * Given a key from Trust associated with a HS Role from a Metadata Entity Descriptor,
     * verify the SAML Signature.
     * 
     * TODO: Replace this with calls into pluggable Trust provider
     * 
     * @param obj           A signed SAMLObject
     * @param signerName    The signer's ID
     * @param ks            KeyStore [TrustProvider abstraction violation, may change]
     * @param knownKey      Key from the Trust entry associated with the signer's Metadata
     * @throws SAMLException
     */
    static void verifySignature(
            SAMLSignedObject obj, 
            String signerName, 
            KeyStore ks, 
            Key knownKey)
        throws SAMLException {
        try {
            NDC.push("verifySignature");
            
            if (!obj.isSigned()) {
                log.error("unable to find a signature");
                throw new TrustException(SAMLException.RESPONDER,
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
                throw new TrustException(SAMLException.RESPONDER,
                "ShibPOSTProfile.verifySignature() can't find any certificates");
            }
            
            // We assume the first one in the set is the end entity cert.
            X509Certificate entity_cert = (X509Certificate) certs_from_obj.next();
            
            // Match the CN of the entity cert with the expected signer.
            String dname = entity_cert.getSubjectDN().getName();
            log.debug("found entity cert with DN: " + dname);
            String cname = "CN=" + signerName;
            if (!dname.equalsIgnoreCase(cname) && !dname.regionMatches(true, 0, cname + ',', 0, cname.length() + 1)) {
                log
                .error("verifySignature() found a mismatch between the entity certificate's DN and the expected signer: "
                        + signerName);
                throw new TrustException(SAMLException.RESPONDER,
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
            throw new TrustException(SAMLException.RESPONDER,
                    "ShibPOSTProfile.verifySignature() unable to build a PKIX certificate path", e);
        } catch (GeneralSecurityException e) {
            log.error("caught a general security exception: " + e.getMessage());
            throw new TrustException(SAMLException.RESPONDER,
                    "ShibPOSTProfile.verifySignature() unable to build a PKIX certificate path", e);
        } finally {
            NDC.pop();
        }
    }

    public static String getHostNameFromDN(X500Principal dn) {
		Matcher matches = regex.matcher(dn.getName(X500Principal.RFC2253));
		if (!matches.find() || matches.groupCount() > 1) {
			log.error("Unable to extract host name name from certificate subject DN.");
			return null;
		}
		return matches.group(1);
	}

    /**
     * @see org.opensaml.SAMLBrowserProfile#setVersion(int, int)
     */
    public void setVersion(int major, int minor) throws SAMLException {
        profile.setVersion(major, minor);
    }

    /**
     * @see org.opensaml.SAMLBrowserProfile#receive(java.lang.StringBuffer, javax.servlet.http.HttpServletRequest, java.lang.String, int, org.opensaml.ReplayCache, org.opensaml.SAMLBrowserProfile.ArtifactMapper)
     */
    public BrowserProfileResponse receive(
            StringBuffer issuer,
            HttpServletRequest reqContext,
            String recipient,
            int supportedProfiles,
            ReplayCache replayCache,
            ArtifactMapper artifactMapper
            ) throws SAMLException {
        
        String providerId = null;
        issuer.setLength(0);
        
        // Let SAML do all the decoding and parsing
        BrowserProfileResponse bpr = profile.receive(issuer, reqContext, providerId, supportedProfiles, replayCache, artifactMapper);
        
        /*
         * Now find the Metadata for the Entity that send this assertion.
         * From the C++, look first for issuer, then namequalifier (for 1.1 compat.)
         */
        EntityDescriptor entity = null;
        String asn_issuer = bpr.assertion.getIssuer();
        String qualifier = bpr.authnStatement.getSubject().getName().getNameQualifier();
        ServiceProviderConfig config = context.getServiceProviderConfig();
        ApplicationInfo appinfo = config.getApplication(applicationId);
        
        entity = appinfo.getEntityDescriptor(asn_issuer);
        providerId=asn_issuer;
        if (entity==null) {
            providerId=qualifier;
            entity= appinfo.getEntityDescriptor(qualifier);
        }
        if (entity==null) {
            log.error("assertion issuer not found in metadata(Issuer ="+
                    issuer+", NameQualifier="+qualifier);
            throw new MetadataException("ShibBrowserProfile.receive() metadata lookup failed, unable to process assertion");
        }
        issuer.append(providerId);
        
        // From the Metadata, get the HS and from it the key
        ProviderRole[] roles = entity.getRoles();
        for (int i=0;i<roles.length;i++) {
            ProviderRole role = roles[i];
            if (role instanceof IDPProviderRole) {
                // TODO: Sync up with new SAML metadata profile (uses SAML protocol string instead of SHIB_NS)
                if (role.hasSupport(XML.SHIB_NS)) {
                    ;
                }
            }
        }
        
        return bpr;
    }
}
