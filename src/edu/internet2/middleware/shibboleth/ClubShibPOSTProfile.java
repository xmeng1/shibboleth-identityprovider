package edu.internet2.middleware.shibboleth;

import java.util.Date;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.*;
import org.w3c.dom.*;

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
     * @param  policies           Array of policy URIs that the implementation
     *      must support
     * @param  mapper             Interface between profile and trust base
     * @param  receiver           URL of SHIRE
     * @param  ttlSeconds         Length of time in seconds allowed to elapse
     *      from issuance of SAML response
     * @exception  SAMLException  Raised if a profile implementation cannot be
     *      constructed from the supplied information
     */
    public ClubShibPOSTProfile(String[] policies, OriginSiteMapper mapper, String receiver, int ttlSeconds)
        throws SAMLException
    {
        super(policies, mapper, receiver, ttlSeconds);
        int i;
        for (i = 0; i < policies.length; i++)
            if (policies[i].equals(Constants.POLICY_CLUBSHIB))
                break;
        if (i == policies.length)
            throw new SAMLException(SAMLException.REQUESTER, "ClubShibPOSTProfile() policy array must include Club Shib");
    }

    /**
     *  HS-side constructor for a ClubShibPOSTProfile object
     *
     * @param  policies           Array of policy URIs that the implementation
     *      must support
     * @param  issuer             "Official" name of issuing origin site
     * @exception  SAMLException  Raised if a profile implementation cannot be
     *      constructed from the supplied information
     */
    public ClubShibPOSTProfile(String[] policies, String issuer)
        throws SAMLException
    {
        super(policies, issuer);
        int i;
        for (i = 0; i < policies.length; i++)
            if (policies[i].equals(Constants.POLICY_CLUBSHIB))
                break;
        if (i == policies.length)
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
            responseCert,
            assertionKey,
            assertionCert);
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
     * @return             The result of signature verification
     */
    protected boolean verifySignature(SAMLSignedObject obj, String signerName, KeyStore ks, Key knownKey)
    {
        if (!super.verifySignature(obj, signerName, ks, knownKey))
            return false;
        return XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1.equals(
            obj.getSignature().getSignedInfo().getSignatureMethodURI()
            );
    }
}

