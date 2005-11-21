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
import java.io.PrintWriter;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLIdentifier;
import org.opensaml.SAMLResponse;

import com.mockrunner.mock.web.MockHttpServletRequest;
import com.mockrunner.mock.web.MockHttpServletResponse;

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
     * 
     * <p>SAML Assertions are good for 60 seconds, so
     * if you want an assertion to be expired set the
     * timestamp back at least a minute.</p>
     * 
     * @param path Path to the input XML file.
     * @param alias Alias in the JKS of the signing key.
     * @param now Date to use for timestamps
     * @param reidentify Option to change response/assertion IDs
     * 
     * @return SAMLResponse now signed
     */
    public SAMLResponse signResponseFile(
            String path, 
            String alias, 
            Date now, 
            boolean reidentify) 
        throws Exception {
        
        InputStream in = new FileInputStream(path);
        
        if (now==null)
            now = new Date(); // default is current time
        SAMLIdentifier defaultIDProvider = ShibbolethRunner.samlConfig.getDefaultIDProvider();
        
        // Read in and parse the XML and turn it into a SAMLResponse
        // [obviously it better be a SAML Response to begin with.]
        SAMLResponse r = new SAMLResponse(in);
        
        if (reidentify)
            r.setId(defaultIDProvider.getIdentifier());
        
        // Retimestamp and resign each assertions
        Iterator assertions = r.getAssertions();
        while (assertions.hasNext()) {
            SAMLAssertion assertion = (SAMLAssertion) assertions.next();
            assertion.setIssueInstant(now);
            assertion.setNotBefore(now);
            assertion.setNotOnOrAfter(new Date(now.getTime() + 60000));
            if (reidentify)
                assertion.setId(defaultIDProvider.getIdentifier());
            assertion.sign(
                    XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1,
                    ks.getKey(alias,passwd),
                    Arrays.asList(ks.getCertificateChain(alias))
                    );
            
        }
        
        // Now resign the Response
        r.sign(
                XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1,
                ks.getKey(alias,passwd),
                Arrays.asList(ks.getCertificateChain(alias))
                );
        
        return r;
    }
    
    public SAMLResponse signResponseFile(
            String path, 
            String alias) throws Exception{
        return signResponseFile(path,alias,null,true);
    }
    
    
    
    /**
     * A dummy Idp that can be used to create a ShibbolethRunner
     * IdPTestContext when the response is to come from a file.
     */
    public class MockIdp extends HttpServlet {
        
        public String ssoResponseFile = null;
        public String artifactResponseFile = null;
        public String attributeResponseFile = null;
        public String alias = "tomcat";
        
        public void init() {}

        public void doGet(HttpServletRequest arg1, 
                HttpServletResponse arg2) 
            throws ServletException, IOException {
            
            MockHttpServletRequest request = (MockHttpServletRequest) arg1;
            MockHttpServletResponse response = (MockHttpServletResponse) arg2;
            
            String uri = request.getRequestURI();
            SAMLResponse r = null;
            
            
            // A very simple test for how to respond.
            
            try {
                if (uri.endsWith("SSO")){
                    r=signResponseFile(ssoResponseFile, alias);
                    request.setAttribute("assertion",new String(r.toBase64()));
                    request.setAttribute("shire",request.getParameter("shire"));
                    request.setAttribute("target",request.getParameter("target"));
                    return;
                }
                if (uri.endsWith("AA")) {
                    r=signResponseFile(attributeResponseFile, alias);
                }
                if (uri.endsWith("Artifact")) {
                    r=signResponseFile(artifactResponseFile, alias);
                }
            } catch (Exception e) {
                throw new ServletException("test file problem");
            }
            
            response.setContentType("text/xml");
            PrintWriter writer = response.getWriter();
            writer.write(r.toString());
            writer.close();
            
        }
    }
    
}
