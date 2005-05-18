/*
 * ShibHttpHook - Receive callbacks from OpenSAML HTTP Session processing.
 * --------------------
 * Copyright 2002, 2004 
 * University Corporation for Advanced Internet Development, Inc. 
 * All rights reserved
 * [Thats all we have to say to protect ourselves]
 * Your permission to use this code is governed by "The Shibboleth License".
 * A copy may be found at http://shibboleth.internet2.edu/license.html
 * [Nothing in copyright law requires license text in every file.]
 * 
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

import edu.internet2.middleware.shibboleth.common.Credential;
import edu.internet2.middleware.shibboleth.common.Credentials;
import edu.internet2.middleware.shibboleth.common.Trust;
import edu.internet2.middleware.shibboleth.metadata.AttributeAuthorityDescriptor;

/**
 * A callback object added to the SAML Binding by Shib. During
 * HTTP session establishment and Request/Response processing 
 * to the AA, SAML calls these exists. This code traps HTTPS
 * sessions and adds a JSSE TrustManager to process Certificates.
 * 
 * @author Howard Gilbert
 *
 */
public class ShibHttpHook implements HTTPHook {

    private static Logger log = Logger.getLogger(HTTPHook.class);
    
    ServiceProviderContext context = ServiceProviderContext.getInstance();
    ServiceProviderConfig config = context.getServiceProviderConfig();
    Credentials credentials = config.getCredentials();
    AttributeAuthorityDescriptor role;
    Trust trust;
    
    /**
     * @param role
     */
    public ShibHttpHook(AttributeAuthorityDescriptor role, Trust trust) {
        super();
        this.role = role;
        this.trust = trust;
    }

    public boolean incoming(HttpServletRequest r, Object globalCtx,
            Object callCtx) throws SAMLException {
        // Not used
        return true;
    }

    public boolean outgoing(HttpServletResponse r, Object globalCtx,
            Object callCtx) throws SAMLException {
        // Not used
        return true;
    }

    public boolean incoming(HttpURLConnection conn, Object globalCtx,
            Object callCtx) throws SAMLException {
        // Not used
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
        if (!(conn instanceof HttpsURLConnection)) {
            return true; // http: sessions need no processing
        }
        HttpsURLConnection sslconn = (HttpsURLConnection) conn;
        SSLContext sslContext = null;
        try {
            sslContext = SSLContext.getInstance("SSL");
        } catch (NoSuchAlgorithmException e) {
            log.error("Cannot find required SSL support");
            return true;
        }
        TrustManager[] tms = new TrustManager[] {new ShibTrustManager()};
        KeyManager[] kms = new KeyManager[] {new ShibKeyManager()};
        try {
            sslContext.init(kms,tms,new java.security.SecureRandom());
        } catch (KeyManagementException e) {
            return false;
        }
        SSLSocketFactory socketFactory = sslContext.getSocketFactory();
        sslconn.setSSLSocketFactory(socketFactory);
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
            Credential credential = credentials.getCredential();
            X509Certificate[] certificateChain = credential.getX509CertificateChain();
            return certificateChain;
        }

        public PrivateKey getPrivateKey(String arg0) {
            // TODO Get the SP Private Key from the Credentials object.
            Credential credential = credentials.getCredential();
            PrivateKey privateKey = credential.getPrivateKey();
            return privateKey;
        }
        
    }
    
    /**
     * Called to approve or reject the Server Certificate of the AA.
     */
    class ShibTrustManager  implements X509TrustManager {

        public X509Certificate[] getAcceptedIssuers() {
            // Not needed, the Server has only one Certificate to send us.
            return new X509Certificate[0]; 
        }
        
        public void checkClientTrusted(X509Certificate[] arg0, String arg1) 
            throws CertificateException {
            // Not used, we are the client
        }

        public void checkServerTrusted(X509Certificate[] certs, String arg1) 
            throws CertificateException {
            if (trust.validate(certs[0],certs,role))
                return;
            //throw new CertificateException("Cannot validate AA Server Certificate in Metadata");
            
        }
        
    }

}
