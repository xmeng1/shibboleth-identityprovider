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

package edu.internet2.middleware.shibboleth.runner;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;

import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLResponse;

/**
 * Class that signs and resets the timestamps on SAML objects.
 * 
 * <p>SAML Responses and Assertions must be signed and they have
 * expiration times that are very short. This makes static files
 * of test cases hard to use. This class promiscuously signs 
 * any static assertion in an XML file with credentials supplied
 * in a JKS and it resets the timestamps. It is used to support
 * JUnit testing where signed input is required.</p>
 * 
 * @author gilbert
 *
 */
public class MadSignertest {

    private KeyStore ks = null;
    private char[] passwd;

    /**
     * Create a signer associated with a JKS file
     * @param path The JKS file path
     * @param password The password of the JKS file and all its Keys.
     */
    public MadSignertest(String path, String password) 
        throws KeyStoreException, 
            NoSuchAlgorithmException, 
            CertificateException, 
            FileNotFoundException, 
            IOException {
        passwd = password.toCharArray();
        ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(path), passwd);
    }
    
    /**
     * Sign the SAMLResponse in a test data xml file.
     * @param path Path to the input XML file.
     * @param alias Alias in the JKS of the signing key.
     * @param now Date to use for timestamps
     * @return SAMLResponse now signed
     */
    public SAMLResponse signResponseFile(String path, String alias, Date now) 
        throws Exception {
        InputStream in = new FileInputStream(path);
        
        if (now==null)
            now = new Date();
        
        SAMLResponse r = new SAMLResponse(in);
        
        Iterator assertions = r.getAssertions();
        while (assertions.hasNext()) {
            SAMLAssertion assertion = (SAMLAssertion) assertions.next();
            assertion.setIssueInstant(now);
            assertion.setNotBefore(now);
            assertion.setNotOnOrAfter(new Date(now.getTime() + 60000));
            assertion.sign(
                    XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1,
                    ks.getKey(alias,passwd),
                    Arrays.asList(ks.getCertificateChain(alias))
                    );
            
        }
        r.sign(
                XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1,
                ks.getKey(alias,passwd),
                Arrays.asList(ks.getCertificateChain(alias))
                );
        
        return r;
    }
    
}
