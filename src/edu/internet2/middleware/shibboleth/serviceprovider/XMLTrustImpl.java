/*
 * XMLTrustImpl.java
 * 
 * Trust provider plugin for XML <Trust> configuration data
 * 
 * Logic based on XMLTrust.cpp
 * 
 * A signed SAMLAssertion arrives. It may carry a certificate
 * or not. If it does carry a certificate, are we willing to 
 * belive it? Trust answers that question. The Signature logic
 * in the XML Security jar will validate the SAML Assertion
 * against a key for us, but we have to belive that the key is
 * correct. Whether to trust the key is outside the scope of 
 * XML, Signature, SAML, and the Shibboleth protocol per se.
 * It is an implementation feature.
 * 
 * A pluggable trust element in a Shibboleth configuration
 * file builds or gains access to a collection of keys and/or
 * certificates (that contain keys). Each key/certificate is 
 * associated with one or more subject names that represent
 * Shibboleth services at a particular institution (Entity). 
 * In this case, the keys and certificates are embedded as
 * bin64 data in an XML file, but they could more generally 
 * be in any key storage.
 * 
 * The function of Trust is to determine the Subject name
 * from the SAMLAssertion, look up the key/certificate for
 * that Subject, apply a wildcard where appropriate, and then
 * ask OpenSAML to ask XML Security to validate the assertion
 * given the key. In some cases, the Assertion may be 
 * accompanied by a certificate signed by an authority, in 
 * which case Trust may use its key store to validate the 
 * authority and certificate, and then feed back the offered
 * key from the transmitted certificate back for validation.
 * 
 * The XML Trust file has already been parsed into a DOM by the 
 * ServiceProviderConfig. This class is a logical extension of the
 * ServiceProviderConfig.XMLTrustProviderImpl class that holds that
 * parsed information.
 * 
 * However, while the ServiceProviderConfig class knows how to parse
 * a trust file into its elements, it is up to this class to know
 * what to do with that information. Generally, it creates 
 * java.security objects representing keys and certificates and
 * matches them to names.
 * 
 * Ultimately, the keys and certificates have to be used by the
 * XML Signature classes from Apache. However, the actual interface
 * to Signature services is the responsibility of OpenSAML. This
 * module determines which keys to use or certificates to trust, but
 * then passes the keys on to the OpenSAML layer.
 * 
 * Note: SAML 2.0 Metadata includes a KeyDescriptor for EntityDescriptor
 * and roles, but while there is a placeholder for it in existing code
 * it is not implemented. The current logic manages key information 
 * embedded in a (typically separate) XML configuration file.
 * 
 * Warning: Trust is a very popular class name. There is an obsolete
 * Trust tag in the shibboleth-targetconfig-1.0.xsd, a current tag in
 * shibboleth-trust-1.0.xsd, plus an interface and so on. As a result,
 * there are a bunch of related objects with slightly different names
 * that represent different views of the same information from different
 * layer of the processing.
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

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import org.apache.log4j.Logger;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xmlbeans.XmlException;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAttributeQuery;
import org.opensaml.SAMLObject;
import org.opensaml.SAMLQuery;
import org.opensaml.SAMLRequest;
import org.opensaml.SAMLResponse;
import org.opensaml.SAMLSubjectStatement;
import org.w3.x2000.x09.xmldsig.DSAKeyValueType;
import org.w3.x2000.x09.xmldsig.KeyInfoType;
import org.w3.x2000.x09.xmldsig.KeyValueType;
import org.w3.x2000.x09.xmldsig.RSAKeyValueType;
import org.w3.x2000.x09.xmldsig.RetrievalMethodType;
import org.w3.x2000.x09.xmldsig.X509DataType;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import x0.maceShibbolethTrust1.KeyAuthorityType;
import x0.maceShibbolethTrust1.TrustDocument;
import x0.maceShibbolethTrust1.TrustDocument.Trust;

import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.common.XML;
import edu.internet2.middleware.shibboleth.metadata.EntityDescriptor;
import edu.internet2.middleware.shibboleth.metadata.Metadata;
import edu.internet2.middleware.shibboleth.metadata.RoleDescriptor;


/**
 * An XMLTrustImpl object is created from an external Trust XML file
 * or inline data under the TrustProvider element of an Application
 * 
 * @author Howard Gilbert
 */
public class XMLTrustImpl 
	implements ITrust,
	PluggableConfigurationComponent {
	
	private static Logger log = Logger.getLogger(XMLTrustImpl.class);
	
	// Data extracted from the KeyAuthority elements of the Trust
	private ArrayList/*<KeyAuthorityInfo>*/ keyauths = new ArrayList();
	private Map/*<Subject-String,KeyAuthorityInfo>*/ authMap = new HashMap();
	private KeyAuthorityInfo wildcardKeyAuthorityInfo;
	
	// Data extracted from the KeyInfo elements of the Trust
	private Map/*<Subject-String,KeyInfoInfo>*/ trustKeyMap = new HashMap();
	

	public void initialize(Node dom) 
		throws XmlException,
		ShibbolethConfigurationException {
	    
	    TrustDocument docbean = TrustDocument.Factory.parse(dom);
	    Trust trustbean = docbean.getTrust();
		CertificateFactory certFactory = null;
		try {
			certFactory = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			// Get a modern version of Java, stupid.
			log.error("Unable to process X.509 Certificates.");
			throw new ShibbolethConfigurationException("Unable to process X.509 Certificates.");
		}		
		
		/*
		 * Convert KeyAuthority configuration elements into KeyAuthorityInfo objects.
		 * A KeyAuthority has only X509 certificates (no naked keys). For each
		 * KeyAuthorityInfo, create a collection of subject names and a collection
		 * of certificates. Then index the KeyAuthorityInfo (and all its certificates)
		 * by each subject name.
		 * 
		 * Note: Using a Map to index by subject restricts every subject name to a single
		 * KeyAuthority. If a subject name might be validated by multiple authorities, then
		 * we would need to use a different collection mechanism.
		 */
		
		KeyAuthorityType[] keyAuthorityArray = trustbean.getKeyAuthorityArray();
		for (int i=0;i<keyAuthorityArray.length;i++){
			KeyAuthorityType keyAuthority = keyAuthorityArray[i];
			/*
			 * While I was walking to Saint Ives, I met a file with 7 KeyAuthorities
			 * Each KeyAuthority had 7 Names, but only one KeyInfo
			 * Each KeyInfo had 7 X509Datas
			 * Each X509Datas had 7 X509Certificates
			 * Authorities, Infos, Datas, Certs ...
			 * How many were going to Saint Ives?
			 */
			KeyAuthorityInfo ka = new KeyAuthorityInfo(); 
			KeyInfoType keyInfo = keyAuthority.getKeyInfo();
			ka.subjects = keyAuthority.getKeyNameArray();
			ka.depth = keyAuthority.getVerifyDepth();
			
			X509DataType[] x509DataArray = keyInfo.getX509DataArray();
			for (int idata=0;idata<x509DataArray.length;idata++) {
				X509DataType x509Data = x509DataArray[idata];
				byte[][] certificateArray = x509Data.getX509CertificateArray();
				for (int icert=0;icert<certificateArray.length;icert++) {
					byte [] certbytes = certificateArray[icert];
					try {
						Certificate certificate = certFactory.generateCertificate(new ByteArrayInputStream(certbytes));
						ka.certs.add(certificate);
					} catch (CertificateException e1) {
						log.error("Invalid X.509 certificate in Trust list.");
						throw new ShibbolethConfigurationException("Invalid X.509 certificate in Trust list.");
					}
				}
			}
			
			// Externally referenced objects
			RetrievalMethodType[] retrievalMethodArray = keyInfo.getRetrievalMethodArray();
			for (int iretrieval=0;iretrieval<retrievalMethodArray.length;iretrieval++) {
				RetrievalMethodType method = retrievalMethodArray[iretrieval];
				String type = method.getType();
				String fname = method.getURI();
				if (type.equals(XML.XMLSIG_RETMETHOD_RAWX509)) {
					try {
						Certificate certificate = certFactory.generateCertificate(new FileInputStream(fname));
						ka.certs.add(certificate);
					} catch (FileNotFoundException e1) {
						log.error("RetrievalMethod referenced an unknown file: "+fname );
					} catch (CertificateException e) {
						log.error("RetrievalMethod referenced an certificate file with bad format: "+fname);
					}
				} else if (type.equals(XML.SHIB_RETMETHOD_PEMX509)) {
					// not sure
					try {
						Certificate certificate = certFactory.generateCertificate(new FileInputStream(fname));
						ka.certs.add(certificate);
					} catch (FileNotFoundException e1) {
						log.error("RetrievalMethod referenced an unknown file: "+fname );
					} catch (CertificateException e) {
						log.error("RetrievalMethod referenced an certificate file with bad format: "+fname);
					}
				}
			}
			
			/*
			 * Index all these certificates by all the subject names provided 
			 */
			for (int isubject=0;isubject<ka.subjects.length;isubject++) {
				String subject = ka.subjects[isubject];
				authMap.put(subject,ka);
			}
			if (ka.subjects.length==0) {
				log.warn("found a wildcard KeyAuthority element, make sure this is what you intend");
				wildcardKeyAuthorityInfo=ka;
			}
			keyauths.add(ka);
		}
		
		/*
		 * KeyInfo trust elements can have either X509 certificates or public keys.
		 * Drill down collecting the information and index it by subject name.
		 */
		KeyInfoType[] keyInfoArray = trustbean.getKeyInfoArray();
		
		for (int i=0;i<keyInfoArray.length;i++) {
			KeyInfoType keyInfo = keyInfoArray[i];
			
			KeyInfoInfo keyii = new KeyInfoInfo();
			
			/*
			 * If the KeyInfo has a certificate, then everything is simple. However,
			 * if it has keys, then the XML format for DER or RSA keys is daunting.
			 * The good news is that Apache XML Security already has classes for 
			 * handling KeyInfo XML elements, and maybe that is a simpler path
			 * than trying to parse them ourselves. So on spec, create an 
			 * apache object just to have it around. 
			 */
			Element ele = (Element) keyInfo.newDomNode().getFirstChild();
			org.apache.xml.security.keys.KeyInfo apacheKeyInfo = null;
			try {
				apacheKeyInfo = 
					new org.apache.xml.security.keys.KeyInfo(ele,"file:///opt/shibboleth/");
			} catch (XMLSecurityException e) {
				// Just a test
			}
			
			String[] subjects = keyInfo.getKeyNameArray();
			
			X509DataType[] dataArray = keyInfo.getX509DataArray();
			if (dataArray.length>0) {  // process certificates
				X509DataType x509Data = dataArray[0];
				if (subjects==null)
					subjects = x509Data.getX509SubjectNameArray();
				if (subjects==null) {
					log.error("Ignoring KeyInfo element with no Subject names");
					continue;
				}
				byte[][] certificateArray = x509Data.getX509CertificateArray();
				if (certificateArray.length==0) {
					log.error("Ignoring KeyInfo element with neither keys nor certificates");
					continue;
				}
				
				// Question: can there be more than one certificate?
				byte[] certbytes = certificateArray[0];
				Certificate certificate=null;
				try {
					certificate = certFactory.generateCertificate(new ByteArrayInputStream(certbytes));
				} catch (CertificateException e1) {
					log.error("Invalid X.509 certificate in Trust list.");
					throw new ShibbolethConfigurationException("Invalid X.509 certificate in Trust list.");
				}
				keyii.cert=certificate;
				keyii.key=certificate.getPublicKey();
				// for (subject:subjects)
				for (int isubject=0;isubject<subjects.length;isubject++) {
					String subject=subjects[isubject];
					
					trustKeyMap.put(subject,keyii);
				}
			} else {
				/*
				 * Tutorial Time
				 * 
				 * A "Key" isn't a single value, but rather a collection of parameters.
				 * In the KeyInfo XML element, a KeyValue can have either a DSA or RSA key.
				 * Each key is specified as a set of fields of type ds:CryptoBinary
				 *  (a version of bin64 binary encoding).
				 * Now there are two ways to proceed, and for the moment both are coded
				 * below until we decide which to use.
				 * 
				 * If you continue to use XBeans, then you extract each parameter for the
				 * specific type of key as the byte[] that XBeans converts bin64 into. 
				 * That byte[] can then be converted to a Java BigInteger which can be
				 * passed as an argument to build a Java KeySpec.
				 * A KeySpec Object is a Java object that represents the key as its 
				 * external separate parameters. The last step is to get a KeyFactor
				 * of type "DSA" or "RSA" to convert the KeySpec into a PublicKey object.
				 * 
				 * Alternately, you can abandon XMLBeans and go back to the DOM.
				 * The KeyInfo element can be directly converted into a corresponding
				 * org.apache object of the XML Security packages. Then the apache
				 * classes do all the work of extracting parameters, converting
				 * formats, and they spit out a public key.
				 * 
				 * Both approaches have been coded below to demonstrate. The
				 * preferred solution will be determined by developer discussion.
				 */
				
				
				KeyValueType[] keyValueArray = keyInfo.getKeyValueArray();
				if (keyValueArray.length==0) {
					log.error("Ignoring an empty KeyInfo (with neither keys nor certificates) in the Trust configuration");
					log.error(keyInfo.xmlText());
					continue;
				}
				
				KeyValueType keyValue = keyValueArray[0];
				
				if (keyValue.isSetDSAKeyValue()) {
					DSAKeyValueType dsavalue = keyValue.getDSAKeyValue();
					BigInteger g = new BigInteger(dsavalue.getG());
					BigInteger p = new BigInteger(dsavalue.getP());
					BigInteger q = new BigInteger(dsavalue.getQ());
					BigInteger y = new BigInteger(dsavalue.getY());
					DSAPublicKeySpec dsakeyspec = new DSAPublicKeySpec(y,p,q,g);
					try {
						PublicKey pubkey = KeyFactory.getInstance("DSA").generatePublic(dsakeyspec);
						keyii.key= pubkey;
					} catch (NoSuchAlgorithmException e) {
						log.error("Java crypto library is broken");
						continue;
					} catch (InvalidKeySpecException e) {
						log.error("Invalid key values in KeyInfo");
						continue;
					}
					
				} else if (keyValue.isSetRSAKeyValue()) {
					RSAKeyValueType rsavalue = keyValue.getRSAKeyValue();
					BigInteger modulus = new BigInteger(rsavalue.getModulus());
					BigInteger pubexp  = new BigInteger(rsavalue.getExponent());
					RSAPublicKeySpec rsakeyspec = new RSAPublicKeySpec(modulus,pubexp);
					try {
						PublicKey pubkey = KeyFactory.getInstance("RSA").generatePublic(rsakeyspec);
						keyii.key= pubkey;
					} catch (NoSuchAlgorithmException e) {
						log.error("Java crypto library is broken");
						continue;
					} catch (InvalidKeySpecException e) {
						log.error("Invalid key values in KeyInfo");
						continue;
					}
					
				}
					
				PublicKey pubkey = null;
				try {
					pubkey= apacheKeyInfo.getPublicKey();
					// Uncomment the following line to replace XMLBean with Apache logic
					// keyii.key= pubkey;
				} catch (org.apache.xml.security.keys.keyresolver.KeyResolverException kre) {
					log.error("Bad key in KeyInfo in Trust");
				}
			}
			if (keyii.cert!=null || keyii.key!=null) {
				// for (subject:subjects)
				for (int isubject=0;isubject<subjects.length;isubject++) {
					String subject = subjects[isubject];
					trustKeyMap.put(subject,keyii);
				}
			}
		}
	}

	/**
	 * Validate a signed SAML object from Trust configuration data
	 * 
	 * <p>Implements a method of the ITrust interface.</p>
	 * 
	 * <p>If the caller supplies a Role, then the object is validated against
	 * the keys associated with that remote Entity. Otherwise, the remote
	 * Entity is located from fields within the token object itself.
	 * 
	 * @param token        The SAMLObject to be validated
	 * @param ProviderRole null or the Role object for the source
	 * @param locator      interface for ApplicationInfo.getEntityDescriptor()
	 * @param revocations  null or revocation provider
	 */
	public boolean validate(
			Iterator revocations, 
			RoleDescriptor role,
			SAMLObject token, 
			Metadata locator
				) {
		
		EntityDescriptor entityDescriptor = null;
		
		// Did the caller designate the remote Entity
		if (role!=null)
			entityDescriptor = (EntityDescriptor) role.getEntityDescriptor();
		
		// If not, then search through the SAMLObject for the remote Entity Id
		if (entityDescriptor==null) {
			if (token instanceof SAMLResponse) {
				Iterator assertions = ((SAMLResponse) token).getAssertions();
				while (entityDescriptor==null && assertions.hasNext()) {
					SAMLAssertion assertion = (SAMLAssertion) assertions.next();
					entityDescriptor = getEntityFromAssertion(locator, assertion);
					
				}
			} else if(token instanceof SAMLAssertion){
				SAMLAssertion assertion = (SAMLAssertion) token;
				entityDescriptor = getEntityFromAssertion(locator, assertion);
			} else if (token instanceof SAMLRequest) {
				SAMLRequest request = (SAMLRequest) token;
				SAMLQuery query = request.getQuery();
				if (query!=null && query instanceof SAMLAttributeQuery) {
					String name = ((SAMLAttributeQuery) query).getResource();
					entityDescriptor=locator.lookup(name);
				}
			}
		}
		
		if (entityDescriptor==null) {
			// May need to use wildcard
		}
		
		// The C++ code now checks the KeyDescriptors in the Roles, but that logic
		// only makes sense in SAML 2.0. There are no KeyDescriptors in the current
		// configuration file, and the current implementation of the Role interfaces
		// dummy that call out. So for now I am going to skip it.
		
		
		
		return true;
	}

	/**
	 * Find the metadata EntityDescriptor for the remote Entity from data in the SAMLAssertion.
	 * 
	 * <p>Try the Issuer first, then look through the name qualifiers.
	 * 
	 * @param locator    Metadata Entity finder method from the configuration ApplicationInfo object
	 * @param assertion  SAMLAssertion to be verified
	 * @return           First ntityDescriptor mapped from assertion data fields. 
	 */
	private EntityDescriptor getEntityFromAssertion(Metadata locator, SAMLAssertion assertion) {
		EntityDescriptor entityDescriptor = null;
		entityDescriptor=locator.lookup(assertion.getIssuer());
		if (entityDescriptor!=null) 
			return entityDescriptor;
		Iterator statements = assertion.getStatements();
		while (entityDescriptor==null && statements.hasNext()) {
			SAMLSubjectStatement statement = (SAMLSubjectStatement) statements.next();
			String qname = statement.getSubject().getName().getNameQualifier();
			entityDescriptor=locator.lookup(qname);
		}
		return entityDescriptor;
	}

	public boolean attach(
			Iterator revocations, 
			RoleDescriptor role
				) {
		return false;
	}

	/**
	 * Represent the information extracted from one KeyAuthority Element
	 */
	static private class KeyAuthorityInfo {
		short depth = 1;
		String[] subjects;
		ArrayList/*<Certificate>*/ certs=new ArrayList();
	}
	
	/**
	 * Represent the information extracted from a simple KeyInfo Element
	 */
	static private class KeyInfoInfo {
		PublicKey key;
		Certificate cert;
	}

    /**
     * @return
     */
    public String getSchemaPathname() {
        return null;
    }
}
