/* 
 * The Shibboleth License, Version 1. 
 * Copyright (c) 2002 
 * University Corporation for Advanced Internet Development, Inc. 
 * All rights reserved
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
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement 
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
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT, 
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.common;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import javax.crypto.SecretKey;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.*;
import org.w3c.dom.*;


/**
 *  Basic Shibboleth POST browser profile implementation with basic support for
 *  signing
 *
 * @author     Scott Cantor
 * @created    April 11, 2002
 */
public class ShibPOSTProfile
{
    /**  XML Signature algorithm to apply */
    protected String algorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;

    /**  Policy URIs to attach or check against */
    protected String[] policies = null;

    /**  Official name of issuing site */
    protected String issuer = null;

    /**  Abstract interface into trust base */
    protected OriginSiteMapper mapper = null;

    /**  The URL of the receiving SHIRE */
    protected String receiver = null;

    /**  Seconds allowed to elapse from issuance of response */
    protected int ttlSeconds = 0;

    /**
     *  SHIRE-side constructor for a ShibPOSTProfile object
     *
     * @param  policies           Array of policy URIs that the implementation
     *      must support
     * @param  mapper             Interface between profile and trust base
     * @param  receiver           URL of SHIRE
     * @param  ttlSeconds         Length of time in seconds allowed to elapse
     *      from issuance of SAML response
     * @exception  SAMLException  Raised if a profile implementation cannot be
     *      constructed from the supplied information
     */
    public ShibPOSTProfile(String[] policies, OriginSiteMapper mapper, String receiver, int ttlSeconds)
        throws SAMLException
    {
        if (policies == null || policies.length == 0 || mapper == null ||
            receiver == null || receiver.length() == 0 || ttlSeconds <= 0)
            throw new SAMLException(SAMLException.REQUESTER, "ShibPOSTProfile() found a null or invalid argument");

        this.mapper = mapper;
        this.receiver = receiver;
        this.ttlSeconds = ttlSeconds;
        this.policies = new String[policies.length];
        System.arraycopy(policies, 0, this.policies, 0, policies.length);
    }

    /**
     *  HS-side constructor for a ShibPOSTProfile object
     *
     * @param  policies           Array of policy URIs that the implementation
     *      must support
     * @param  issuer             "Official" name of issuing origin site
     * @exception  SAMLException  Raised if a profile implementation cannot be
     *      constructed from the supplied information
     */
    public ShibPOSTProfile(String[] policies, String issuer)
        throws SAMLException
    {
        if (policies == null || policies.length == 0 || issuer == null || issuer.length() == 0)
            throw new SAMLException(SAMLException.REQUESTER, "ShibPOSTProfile() found a null or invalid argument");
        this.issuer = issuer;
        this.policies = new String[policies.length];
        System.arraycopy(policies, 0, this.policies, 0, policies.length);
    }

    /**
     *  Locates an assertion containing a "bearer" AuthenticationStatement in
     *  the response and validates the enclosing assertion with respect to the
     *  POST profile
     *
     * @param  r          The response to the accepting site
     * @return            An SSO assertion
     */
    public SAMLAssertion getSSOAssertion(SAMLResponse r)
    {
        return SAMLPOSTProfile.getSSOAssertion(r,policies);
    }

    /**
     *  Locates a "bearer" AuthenticationStatement in the assertion and
     *  validates the statement with respect to the POST profile
     *
     * @param  a  The SSO assertion sent to the accepting site
     * @return    A "bearer" authentication statement
     */
    public SAMLAuthenticationStatement getSSOStatement(SAMLAssertion a)
    {
        return (a==null) ? null : SAMLPOSTProfile.getSSOStatement(a);
    }

    /**
     *  Parse a Base-64 encoded buffer back into a SAML response and test its
     *  validity against the POST profile, including use of the default replay
     *  cache<P>
     *
     *  Also does trust evaluation based on the information available from the
     *  origin site mapper, in accordance with general Shibboleth processing
     *  semantics. Club-specific processing must be performed in a subclass.<P>
     *
     *
     *
     * @param  buf                A Base-64 encoded buffer containing a SAML
     *      response
     * @return                    SAML response sent by origin site
     * @exception  SAMLException  Thrown if the response cannot be understood or
     *      accepted
     */
    public SAMLResponse accept(byte[] buf)
        throws SAMLException
    {
        // The built-in SAML functionality will do most of the basic non-crypto checks.
        // Note that if the response only contains a status error, it gets tossed out
        // as an exception.
        SAMLResponse r = SAMLPOSTProfile.accept(buf, receiver, ttlSeconds);

        // Now we do some more non-crypto (ie. cheap) work to match up the origin site
        // with its associated data. If we can't even find a SSO statement in the response
        // we just return the response to the caller, who will presumably notice this.
        SAMLAssertion assertion = getSSOAssertion(r);
        if (assertion == null)
            return r;

        SAMLAuthenticationStatement sso = getSSOStatement(assertion);
        if (sso == null)
            return r;

        // Examine the subject information.
        SAMLSubject subject = sso.getSubject();
        if (subject.getNameQualifier() == null)
            throw new SAMLException(SAMLException.RESPONDER, "ShibPOSTProfile.accept() requires subject name qualifier");

        String originSite = subject.getNameQualifier();
        String handleService = assertion.getIssuer();

        // Is this a trusted HS?
        Iterator hsNames = mapper.getHandleServiceNames(originSite);
        boolean bFound = false;
        while (!bFound && hsNames != null && hsNames.hasNext())
            if (hsNames.next().equals(handleService))
                bFound = true;
        if (!bFound)
            throw new SAMLException(SAMLException.RESPONDER, "ShibPOSTProfile.accept() detected an untrusted HS for the origin site");

        Key hsKey = mapper.getHandleServiceKey(handleService);
        KeyStore ks = mapper.getTrustedRoots();

        // Signature verification now takes place. We check the assertion and the response.
        // Assertion signing is optional, response signing is mandatory.
        if (assertion.getSignature() != null && !verifySignature(assertion, handleService, ks, hsKey))
            throw new SAMLException(SAMLException.RESPONDER, "ShibPOSTProfile.accept() detected an invalid assertion signature");
        if (!verifySignature(r, handleService, ks, hsKey))
            throw new SAMLException(SAMLException.RESPONDER, "ShibPOSTProfile.accept() detected an invalid response signature");

        return r;
    }

    /**
     *  Used by HS to generate a signed SAML response conforming to the POST
     *  profile<P>
     *
     *
     *
     * @param  recipient          URL of intended consumer
     * @param  name               Name of subject
     * @param  nameQualifier      Federates or qualifies subject name (optional)
     * @param  subjectIP          Client address of subject (optional)
     * @param  authMethod         URI of authentication method being asserted
     * @param  authInstant        Date and time of authentication being asserted
     * @param  bindings           Array of SAML authorities the relying party
     *      may contact (optional)
     * @param  responseKey        A secret or private key to use in response
     *      signature or MAC
     * @param  responseCert       A public key certificate to enclose with the
     *      response (optional)
     * @param  assertionKey       A secret or private key to use in assertion
     *      signature or MAC (optional)
     * @param  assertionCert      A public key certificate to enclose with the
     *      assertion (optional)
     * @return                    SAML response to send to accepting site
     * @exception  SAMLException  Base class of exceptions that may be thrown
     *      during processing
     */
    public SAMLResponse prepare(String recipient,
                                String name,
                                String nameQualifier,
                                String subjectIP,
                                String authMethod,
                                Date authInstant,
                                SAMLAuthorityBinding[] bindings,
                                Key responseKey, X509Certificate responseCert,
                                Key assertionKey, X509Certificate assertionCert
                                )
        throws SAMLException
    {
        if (responseKey == null || (!(responseKey instanceof PrivateKey) && !(responseKey instanceof SecretKey)))
            throw new InvalidCryptoException(SAMLException.RESPONDER, "ShibPOSTProfile.prepare() requires a response key (private or secret)");
        if (assertionKey != null && !(assertionKey instanceof PrivateKey) && !(assertionKey instanceof SecretKey))
            throw new InvalidCryptoException(SAMLException.RESPONDER, "ShibPOSTProfile.prepare() detected an invalid type of assertion key");

        DocumentBuilder builder = null;
        try
        {
            builder = org.opensaml.XML.parserPool.get();
            Document doc = builder.newDocument();

            XMLSignature rsig = new XMLSignature(doc, null, algorithm);
            XMLSignature asig = null;
            if (assertionKey != null)
                asig = new XMLSignature(doc, null, algorithm);

            SAMLResponse r = SAMLPOSTProfile.prepare(
                recipient,
                issuer,
                policies,
                name,
                nameQualifier,
                null,
                subjectIP,
                authMethod,
                authInstant,
                bindings,
                rsig,
                asig);
            r.toDOM(doc);
            if (asig != null)
            {
                if (assertionCert != null)
                    asig.addKeyInfo(assertionCert);
                if (assertionKey instanceof PrivateKey)
                    asig.sign((PrivateKey)assertionKey);
                else
                    asig.sign((SecretKey)assertionKey);
            }
            if (responseCert != null)
                rsig.addKeyInfo(responseCert);
            if (responseKey instanceof PrivateKey)
                rsig.sign((PrivateKey)responseKey);
            else
                rsig.sign((SecretKey)responseKey);
            return r;
        }
        catch (ParserConfigurationException pce)
        {
            throw new SAMLException(SAMLException.RESPONDER, "ShibPOSTProfile.prepare() unable to obtain XML parser instance: " + pce.getMessage(), pce);
        }
        catch (XMLSecurityException e)
        {
            throw new InvalidCryptoException(SAMLException.RESPONDER, "ShibPOSTProfile.prepare() detected an XML security problem during signature creation", e);
        }
        finally
        {
            if (builder != null)
                org.opensaml.XML.parserPool.put(builder);
        }
    }

    /**
     *  Searches the replay cache for the specified assertion and inserts a
     *  newly seen assertion into the cache<P>
     *
     *  Also performs garbage collection of the cache by deleting expired
     *  entries.
     *
     * @param  a            The assertion to check
     * @return              true iff the assertion has not been seen before
     */
    public synchronized boolean checkReplayCache(SAMLAssertion a)
    {
        // Default implementation uses the basic replay cache implementation.
        return SAMLPOSTProfile.checkReplayCache(a);
    }

    /**
     *  Default signature verification algorithm uses an embedded X509
     *  certificate or an explicit key to verify the signature. The certificate
     *  is examined to insure the subject CN matches the signer, and that it is
     *  signed by a trusted CA
     *
     * @param  obj         The object containing the signature
     * @param  signerName  The name of the signer
     * @param  ks          A keystore containing trusted root certificates
     * @param  knownKey    An explicit key to use if a certificate cannot be
     *      found
     * @return             The result of signature verification
     */
    protected boolean verifySignature(SAMLSignedObject obj, String signerName, KeyStore ks, Key knownKey)
    {
        try
        {
            XMLSignature sig = (obj != null) ? obj.getSignature() : null;
            if (sig == null)
                return false;
            KeyInfo ki = sig.getKeyInfo();
            if (ks != null && ki != null)
            {
                X509Certificate cert = ki.getX509Certificate();
                if (cert != null)
                {
                    cert.checkValidity();
                    if (!sig.checkSignatureValue(cert))
                        return false;
                    if (signerName != null)
                    {
                        String dname = cert.getSubjectDN().getName();
                        String cname = "CN=" + signerName;
                        if (!dname.equalsIgnoreCase(cname) && !dname.regionMatches(true, 0, cname + ',', 0, cname.length() + 1))
                            return false;
                    }

                    String iname = cert.getIssuerDN().getName();
                    for (Enumeration aliases = ks.aliases(); aliases.hasMoreElements(); )
                    {
                        String alias = (String)aliases.nextElement();
                        if (!ks.isCertificateEntry(alias))
                            continue;
                        Certificate cacert = ks.getCertificate(alias);
                        if (!(cacert instanceof X509Certificate))
                            continue;
                        if (iname.equals(((X509Certificate)cacert).getSubjectDN().getName()))
                        {
                            cert.verify(cacert.getPublicKey());
                            ((X509Certificate)cacert).checkValidity();
                            return true;
                        }
                    }

                    return false;
                }
            }
            return (knownKey != null) ? sig.checkSignatureValue(knownKey) : false;
        }
        catch (XMLSecurityException e)
        {
            e.printStackTrace();
            return false;
        }
        catch (GeneralSecurityException e)
        {
            e.printStackTrace();
            return false;
        }
    }
}

