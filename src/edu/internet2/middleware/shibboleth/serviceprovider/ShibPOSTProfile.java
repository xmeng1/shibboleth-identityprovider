/*
 * ShibPOSTProfile.java
 * 
 * ServiceProvider (Target) front end to the SAMLPOSTProfile
 * function. 
 * 
 * The ...common.ShibPOSTProfile class contained a 
 * prototype Target-side accept() method. However, it did
 * had not been used, did not exactly track the C++ logic, 
 * and was missing the Metadata interface. Yet that code
 * was being used for the Origin. So it seemed safer to
 * build a separate Target-only module here borrowing code
 * from the other module that was complete but tracking as
 * closely as possible the C++ logic.
 * 
 * --------------------
 * Copyright 2002, 2004 
 * University Corporation for Advanced Internet Development, Inc. 
 * All rights reserved
 * [Thats all we have to say to protect ourselves]
 * Your permission to use this code is governed by "The Shibboleth License".
 * A copy may be found at http://shibboleth.internet2.edu/license.html
 * [Nothing in copyright law requires license text in every file.]
 */
package edu.internet2.middleware.shibboleth.serviceprovider;

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
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.Vector;

import org.apache.log4j.Logger;
import org.apache.log4j.NDC;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAuthenticationStatement;
import org.opensaml.SAMLException;
import org.opensaml.SAMLPOSTProfile;
import org.opensaml.SAMLResponse;
import org.opensaml.SAMLSignedObject;
import org.opensaml.TrustException;

import edu.internet2.middleware.shibboleth.common.XML;
import edu.internet2.middleware.shibboleth.metadata.EntityDescriptor;
import edu.internet2.middleware.shibboleth.metadata.IDPProviderRole;
import edu.internet2.middleware.shibboleth.metadata.MetadataException;
import edu.internet2.middleware.shibboleth.metadata.ProviderRole;
import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderConfig.ApplicationInfo;

/**
 * @author Howard Gilbert
 */
public class ShibPOSTProfile {

	
	private static Logger log = Logger.getLogger(ShibPOSTProfile.class);
	private static ServiceProviderContext context = ServiceProviderContext.getInstance();
	
	/*
	 * The C++ class is constructed by passing enumerations of Metadata
	 * providers, trust providers, etc from the <Application>. However,
	 * those providers can change dynamically. This version only keeps
	 * the applicationId that can be used to fetch the ApplicationInfo 
	 * object and, from it, get the collections of provider plugins.
	 */
	private String applicationId = null;
	
	/**
	 * Identify the <Application> from which to get plugins.
	 * 
	 * @param applicationId 
	 */
	public ShibPOSTProfile(String applicationId) {
		this.applicationId = applicationId;
	}
	
	// Pass through to SAMLPOSTProfile
    public static SAMLAssertion getSSOAssertion(SAMLResponse r, Collection audiences)
    	throws SAMLException {
    	return SAMLPOSTProfile.getSSOAssertion(r,audiences);
    }
	
    // Pass through to SAMLPOSTProfile
    public static SAMLAuthenticationStatement getSSOStatement(SAMLAssertion a)
    	throws SAMLException {
    	return SAMLPOSTProfile.getSSOStatement(a);
    }
    
    /**
     * Favor AuthnStatement Subject NameQualifer, but use Issuer if need be
     * @param r SAMLResponse
     * @return NameQualifier or Issuer
     */
    public String getProviderId(SAMLResponse r) {
    	String providerId=null;
    	Iterator ia = r.getAssertions();
    	while (ia.hasNext()) {
    		SAMLAssertion a = (SAMLAssertion) ia.next();
    		providerId = a.getIssuer();
    		Iterator is = a.getStatements();
    		while (is.hasNext()) {
    			SAMLAuthenticationStatement as = 
    				(SAMLAuthenticationStatement) is.next();
    			if (as!=null) {
    				 String ret = as.getSubject().getName().getNameQualifier();
    				 if (ret!=null)
    				 	return ret;
    			}
    		}
    	}
		return providerId;
    	
    }
    
    /**
     * Process the Base64 encoded SAML Authentication Assertion
     * from the Form Field filled in by HS and transmitted by the
     * Browser.
     * 
     * @param buf Array of bytes from the form
     * @param recipient 
     * @param ttlSeconds
     * @param audiences
     * @param pproviderId  StringBuffer secondary return of providerId
     * @return SAMLResponse encoded in buffer
     * @throws SAMLException if SAML Assertion structure is invalid
     * @throws MetadataException if Origin site missing from metadata
     */
    SAMLResponse accept(
    		byte[]buf, 
			String recipient, 
			int ttlSeconds, 
			String[] audiences,
			StringBuffer pproviderId
			) throws SAMLException, MetadataException {
    	
    	String providerId = null;
    	pproviderId.setLength(0);
    	SAMLAssertion assertion = null;
    	SAMLAuthenticationStatement sso = null;
    	SAMLResponse r = null;
    	
    	// Let SAML do all the decoding and parsing
		r = SAMLPOSTProfile.accept(buf,recipient,ttlSeconds,false);
		
		// Drill down through the objects
		assertion = getSSOAssertion(r,Arrays.asList(audiences));
		sso = getSSOStatement(assertion);
		
		// Check recipient and timeout, but not the signature
		// throws SAMLException if checks fail
		SAMLPOSTProfile.process(r,recipient,ttlSeconds);
		
		/*
		 * Now find the Metadata for the Entity that send this assertion.
		 * From the C++, look first for issuer, then namequalifier
		 */
		EntityDescriptor entity = null;
		String issuer = assertion.getIssuer();
		String qualifier = sso.getSubject().getName().getNameQualifier();
		ServiceProviderConfig config = context.getServiceProviderConfig();
		ApplicationInfo appinfo = config.getApplication(applicationId);
		
		
		entity = appinfo.getEntityDescriptor(issuer);
		providerId=issuer;
		if (entity==null) {
		    providerId=qualifier;
			entity= appinfo.getEntityDescriptor(qualifier);
		}
		if (entity==null) {
			log.error("assertion issuer not found in metadata(Issuer ="+
					issuer+", NameQualifier="+qualifier);
			throw new MetadataException("ShibPOSTProfile accept() metadata lookup failed, unable to process assertion");
		}
		pproviderId.append(providerId);
		
		// From the Metadata, get the HS and from it the key
		ProviderRole[] roles = entity.getRoles();
		for (int i=0;i<roles.length;i++) {
			ProviderRole role = roles[i];
			if (role instanceof IDPProviderRole) {
				if (role.hasSupport(XML.SHIB_NS)) {
					;
				}
			}
		}
		
		return r;
    }
    
    /**
     * Given a key from Trust associated with a HS Role from a Metadata Entity Descriptor,
     * verify the SAML Signature.
     * 
     * <p>Note: This routine was copied from ...common.ShibPOSTProfile. Will be changed
     * as needed.</p>
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
    
}
