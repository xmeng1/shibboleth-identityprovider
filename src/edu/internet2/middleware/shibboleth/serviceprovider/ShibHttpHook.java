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

/*
 * ShibHttpHook - Receive callbacks from OpenSAML HTTP Session processing.
 */
package edu.internet2.middleware.shibboleth.serviceprovider;

import java.net.HttpURLConnection;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.opensaml.SAMLException;
import org.opensaml.SAMLSOAPHTTPBinding.HTTPHook;

import edu.internet2.middleware.shibboleth.common.Constants;
import edu.internet2.middleware.shibboleth.common.Credential;
import edu.internet2.middleware.shibboleth.common.Credentials;
import edu.internet2.middleware.shibboleth.common.Trust;
import edu.internet2.middleware.shibboleth.metadata.AttributeAuthorityDescriptor;

/**
 * During Attribute Query, SAML creates the HTTP(S) session with
 * the AA. Objects of this class provide a callback for special
 * processing of the Session that SAML has established before data
 * is exchanged. This allows Shib to add its own Metadata and Trust
 * processing to validate the AA identity.
 
 * @author Howard Gilbert
 *
 */
public class ShibHttpHook implements HTTPHook {

    private static Logger log = Logger.getLogger(HTTPHook.class);
    
    ServiceProviderContext context = ServiceProviderContext.getInstance();
    ServiceProviderConfig config = context.getServiceProviderConfig();
    
    // If we present a ClientCert, it will be this one.
    Credentials credentials = config.getCredentials();
    
    // SAML Doesn't know the Shibboleth objects, so they have to be saved
    // by the constructor so they can be used in callbacks without being
    // passed as arguments
    AttributeAuthorityDescriptor role; // The AA object from the Metadata
    Trust trust; // A ShibbolethTrust object
    
    /**
     * @param role
     */
    public ShibHttpHook(AttributeAuthorityDescriptor role, Trust trust) {
        super();
        this.role = role;  // Save the AA Role for the callback
        this.trust = trust; // Save the ShibTrust for the callback
    }

    public boolean incoming(HttpServletRequest r, Object globalCtx,
            Object callCtx) throws SAMLException {
        log.error("ShibHttpHook method incoming-1 should not have been called.");
        return true;
    }

    public boolean outgoing(HttpServletResponse r, Object globalCtx,
            Object callCtx) throws SAMLException {
        log.error("ShibHttpHook method outgoing-1 should not have been called.");
        return true;
    }

    public boolean incoming(HttpURLConnection conn, Object globalCtx,
            Object callCtx) throws SAMLException {
        // Called with the AA response, but I have nothing to add here
        return true;
    }

    /**
     * After the URLConnection has been initialized and before 
     * the connect() method is called, this exit has a chance to
     * do additional processing.
     * 
     * <p>If this is an HTTPS session, configure the SocketFactory
     * to use a custom TrustManager for Certificate processing.</p>
     */
    public boolean outgoing(HttpURLConnection conn, Object globalCtx,
            Object callCtx) throws SAMLException {
    	
    	conn.setRequestProperty("Shibboleth", Constants.SHIB_VERSION);
    	
        if (!(conn instanceof HttpsURLConnection)) {
            return true; // HTTP (non-SSL) sessions need no additional processing
        }
        // Cast to subclass with extra info
        HttpsURLConnection sslconn = (HttpsURLConnection) conn;
        
        // To get your own Certificate Processing exits, you have 
        // to create a custom SSLContext, configure it, and then
        // obtain a SocketFactory
        SSLContext sslContext = null;
        try {
            sslContext = SSLContext.getInstance("SSL");
        } catch (NoSuchAlgorithmException e) {
            // Cannot happen in code that is already doing SSL
            log.error("Cannot find required SSL support");
            return true;
        }
        
        // Arrays with one element (for init)
        TrustManager[] tms = new TrustManager[] {new ShibTrustManager()};
        KeyManager[] kms = new KeyManager[] {new ShibKeyManager()};
        
        try {
            // Attach the KeyManager and TrustManager to the Context
            sslContext.init(kms,tms,new java.security.SecureRandom());
        } catch (KeyManagementException e) {
            return false;
        }
        
        // Now we can get our own custom SocketFactory and replace
        // the default factory in the caller's URLConnection
        SSLSocketFactory socketFactory = sslContext.getSocketFactory();
        sslconn.setSSLSocketFactory(socketFactory);
        
        // The KeyManager and TrustManager get callbacks from JSSE during
        // the URLConnection.connect() call
        return true;
    }
    
    /**
     * Called to select the Client Certificate the SP will present to 
     * the AA.
     * 
     * <p>Normally a user KeyManager extends some class backed by a 
     * KeyStore. It just chooses an alias, and lets the parent class 
     * do the dirty work of extracting the Certificate chain from the 
     * backing file. However, in Shibboleth the SP Credentials come
     * from the configuration file and are in memory. There is no
     * meaningful alias, so we make one up.
     */
    class ShibKeyManager implements X509KeyManager {
        
        public String fred ="Fred";
        public String[] freds = {fred};

        public String[] getClientAliases(String arg0, Principal[] arg1) {
            return freds;
        }

        public String chooseClientAlias(String[] arg0, Principal[] arg1, Socket arg2) {
            return fred;
        }

        public String[] getServerAliases(String arg0, Principal[] arg1) {
            return freds;
        }

        public String chooseServerAlias(String arg0, Principal[] arg1, Socket arg2) {
            return fred;
        }

        public X509Certificate[] getCertificateChain(String arg0) {
            // Obtain the Client Cert from the Credentials object
            // in the configuration file. Ignore argument "fred".
            Credential credential = credentials.getCredential();
            X509Certificate[] certificateChain = credential.getX509CertificateChain();
            return certificateChain;
        }

        public PrivateKey getPrivateKey(String arg0) {
            // Obtain the Private Key from the Credentials object.
            Credential credential = credentials.getCredential();
            PrivateKey privateKey = credential.getPrivateKey();
            return privateKey;
        }
        
    }
    
    /**
     * Called to approve or reject an SSL Server Certificate.
     * In practice this is the Certificate of the AA.
     * 
     * <p>A TrustManager handles Certificate approval at either end
     * of an SSL connection, but this code is in the SP and is only 
     * inserted into the Attribute Query to the AA. When the AA is
     * configured to use HTTPS and presents an SSL Server Certficate,
     * call the commmon code to validate that this Certificate is in
     * the Metadata.</p>
     */
    class ShibTrustManager  implements X509TrustManager {

        public X509Certificate[] getAcceptedIssuers() {
            log.error("ShibHttpHook method getAcceptedIssuers should not have been called.");
            return new X509Certificate[0]; 
        }
        
        public void checkClientTrusted(X509Certificate[] arg0, String arg1) 
            throws CertificateException {
            log.error("ShibHttpHook method checkClientTrusted should not have been called.");
        }

        public void checkServerTrusted(X509Certificate[] certs, String arg1) 
            throws CertificateException {
            if (trust.validate(certs[0],certs,role)) {
                log.debug("ShibHttpHook accepted AA Server Certificate.");
                return;
            }
            log.info("ShibHttpHook rejected AA Server Certificate.");
            throw new CertificateException("Cannot validate AA Server Certificate in Metadata");
            
        }
        
    }

}
