package edu.internet2.middleware.shibboleth;

import java.security.Key;
import org.opensaml.SAMLException;
import org.opensaml.SAMLPOSTProfile;

/**
 *  Used by Shibboleth HS/SHIRE to locate a Shibboleth POST profile
 *  implementation
 *
 * @author     Scott Cantor
 * @created    April 10, 2002
 */
public class ShibPOSTProfileFactory
{
    /**
     *  Gets a compatible SHIRE-side profile implementation for the specified
     *  policies
     *
     * @param  policies           Array of policy URIs that the implementation
     *      must support
     * @param  mapper             Interface between profile and trust base
     * @param  receiver           URL of SHIRE
     * @param  ttlSeconds         Length of time in seconds allowed to elapse
     *      from issuance of SAML response
     * @return                    A compatible profile implementation or null if
     *      one cannot be found
     * @exception  SAMLException  Raised if a profile implementation cannot be
     *      constructed from the supplied information
     */
    public static ShibPOSTProfile getInstance(String[] policies, OriginSiteMapper mapper,
                                              String receiver, int ttlSeconds)
        throws SAMLException
    {
        // Current version only knows about Club Shib...
        if (policies == null || policies.length != 1 || !policies[0].equals(Constants.POLICY_CLUBSHIB))
            return null;

        if (mapper == null || receiver == null || ttlSeconds <= 0)
            return null;

        return new ClubShibPOSTProfile(policies, mapper, receiver, ttlSeconds);
    }

    /**
     *  Gets a compatible HS-side profile implementation for the specified
     *  policies
     *
     * @param  policies           Array of policy URIs that the implementation
     *      must support
     * @param  issuer             "Official" name of issuing origin site
     * @return                    A compatible profile implementation or null if
     *      one cannot be found
     * @exception  SAMLException  Raised if a profile implementation cannot be
     *      constructed from the supplied information
     */
    public static ShibPOSTProfile getInstance(String[] policies, String issuer)
        throws SAMLException
    {
        // Current version only knows about Club Shib...
        if (policies == null || policies.length != 1 || !policies[0].equals(Constants.POLICY_CLUBSHIB))
            return null;

        if (issuer == null || issuer.length() == 0)
            return null;

        return new ClubShibPOSTProfile(policies, issuer);
    }
}

