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
import java.util.Iterator;
import java.util.Vector;

import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.apache.log4j.NDC;
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.NoSuchProviderException;
import org.opensaml.ReplayCache;
import org.opensaml.SAMLBrowserProfile;
import org.opensaml.SAMLBrowserProfileFactory;
import org.opensaml.SAMLException;
import org.opensaml.SAMLSignedObject;
import org.opensaml.TrustException;

import edu.internet2.middleware.shibboleth.metadata.EntityDescriptor;
import edu.internet2.middleware.shibboleth.metadata.MetadataException;
import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderConfig;
import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderContext;
import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderConfig.ApplicationInfo;

// TODO: Suggest we implement a separation layer between the SP config pieces and the input needed
// for this class. As long as metadata/etc. are shared, this should work.

/**
 * Basic Shibboleth POST browser profile implementation with basic support for signing
 * 
 * @author Scott Cantor @created April 11, 2002
 */
public class ShibBrowserProfile implements SAMLBrowserProfile {



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



    /**
     * @see org.opensaml.SAMLBrowserProfile#receive(java.lang.StringBuffer, javax.servlet.http.HttpServletRequest, java.lang.String, int, org.opensaml.ReplayCache, org.opensaml.SAMLBrowserProfile.ArtifactMapper, int)
     */
    public BrowserProfileResponse receive(
            StringBuffer issuer,
            HttpServletRequest reqContext,
            String recipient,
            int supportedProfiles,
            ReplayCache replayCache,
            ArtifactMapper artifactMapper,
            int minorVersion
            ) throws SAMLException {
        
        String providerId = null;
        issuer.setLength(0);
        
        // Let SAML do all the decoding and parsing
        BrowserProfileResponse bpr = profile.receive(issuer, reqContext, recipient, supportedProfiles, replayCache, artifactMapper, minorVersion);
        
        /*
         * Now find the Metadata for the Entity that send this assertion.
         * From the C++, look first for issuer, then namequalifier (for 1.1 compat.)
         */
        EntityDescriptor entity = null;
        String asn_issuer = bpr.assertion.getIssuer();
        String qualifier = bpr.authnStatement.getSubject().getNameIdentifier().getNameQualifier();
        ServiceProviderConfig config = context.getServiceProviderConfig();
        ApplicationInfo appinfo = config.getApplication(applicationId);
        
        entity = appinfo.lookup(asn_issuer);
        providerId=asn_issuer;
        if (entity==null) {
            providerId=qualifier;
            entity= appinfo.lookup(qualifier);
        }
        if (entity==null) {
            log.error("assertion issuer not found in metadata(Issuer ="+
                    issuer+", NameQualifier="+qualifier);
            throw new MetadataException("ShibBrowserProfile.receive() metadata lookup failed, unable to process assertion");
        }
        issuer.append(providerId);
        
        // TODO: finish profile extension using metadata/trust interfaces
        
        return bpr;
    }
}
