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

import java.security.Key;
import java.security.KeyStore;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collection;
import java.util.Date;

import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.*;

/**
 *  ClubShib-specific POST browser profile implementation
 *
 * @author     Scott Cantor
 * @created    April 11, 2002
 */
public class ClubShibPOSTProfile extends ShibPOSTProfile
{
    /**
     *  SHIRE-side constructor for a ClubShibPOSTProfile object
     *
     * @param  policies           Set of policy URIs that the implementation
     *      must support
     * @param  receiver           URL of SHIRE
     * @param  ttlSeconds         Length of time in seconds allowed to elapse
     *      from issuance of SAML response
     * @exception  SAMLException  Raised if a profile implementation cannot be
     *      constructed from the supplied information
     */
    public ClubShibPOSTProfile(Collection policies, String receiver, int ttlSeconds)
        throws SAMLException
    {
        super(policies, receiver, ttlSeconds);
        if (!policies.contains(Constants.POLICY_CLUBSHIB))
            throw new SAMLException(SAMLException.REQUESTER, "ClubShibPOSTProfile() policy array must include Club Shib");
    }

    /**
     *  HS-side constructor for a ClubShibPOSTProfile object
     *
     * @param  policies           Set of policy URIs that the implementation
     *      must support
     * @param  issuer             "Official" name of issuing origin site
     * @exception  SAMLException  Raised if a profile implementation cannot be
     *      constructed from the supplied information
     */
    public ClubShibPOSTProfile(Collection policies, String issuer)
        throws SAMLException
    {
        super(policies, issuer);
        if (!policies.contains(Constants.POLICY_CLUBSHIB))
            throw new SAMLException(SAMLException.RESPONDER, "ClubShibPOSTProfile() policy array must include Club Shib");
    }

    /**
     *  Used by HS to generate a signed SAML response conforming to the POST
     *  profile<P>
     *
     *  Club Shib specifies use of the RSA algorithm with RSA public keys and
     *  X.509 certificates.
     *
     * @param  recipient          URL of intended consumer
     * @param  name               Name of subject
     * @param  nameQualifier      Federates or qualifies subject name (optional)
     * @param  subjectIP          Client address of subject (optional)
     * @param  authMethod         URI of authentication method being asserted
     * @param  authInstant        Date and time of authentication being asserted
     * @param  bindings           Set of SAML authorities the relying party
     *      may contact (optional)
     * @param  responseKey        A secret or private key to use in response
     *      signature or MAC
     * @param  responseCert       One or more X.509 certificates to enclose with the
     *      response (optional)
     * @param  assertionKey       A secret or private key to use in assertion
     *      signature or MAC (optional)
     * @param  assertionCert      One or more X.509 certificates to enclose with the
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
                                Collection bindings,
                                Key responseKey, Collection responseCerts,
                                Key assertionKey, Collection assertionCerts
                                )
        throws SAMLException
    {
        if (responseKey == null || !(responseKey instanceof RSAPrivateKey))
            throw new InvalidCryptoException(SAMLException.RESPONDER, "ClubShibPOSTProfile.prepare() requires the response key be an RSA private key");
        if (assertionKey != null && !(assertionKey instanceof RSAPrivateKey))
            throw new InvalidCryptoException(SAMLException.RESPONDER, "ClubShibPOSTProfile.prepare() requires the assertion key be an RSA private key");

        return super.prepare(
            recipient,
            name,
            nameQualifier,
            subjectIP,
            authMethod,
            authInstant,
            bindings,
            responseKey,
            responseCerts,
            assertionKey,
            assertionCerts);
    }

    /**
     *  Club Shib signature verification implements additional checks for the
     *  RSA and SHA-1 algorithms.
     *
     * @param  obj         The object containing the signature
     * @param  signerName  The name of the signer
     * @param  ks          A keystore containing trusted root certificates
     * @param  knownKey    An explicit key to use if a certificate cannot be
     *      found
     * @param  simple      Verify according to simple SAML signature profile?
     *
     * @throws SAMLException    Thrown if the signature cannot be verified
     */
    protected void verifySignature(SAMLSignedObject obj, String signerName, KeyStore ks, Key knownKey, boolean simple)
        throws SAMLException
    {
        super.verifySignature(obj, signerName, ks, knownKey, simple);
        if (!obj.getSignatureAlgorithm().equals(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1))
            throw new TrustException(SAMLException.RESPONDER, "ClubShibPOSTProfile.verifySignature() requires the RSA-SHA1 signature algorithm");
    }
}

