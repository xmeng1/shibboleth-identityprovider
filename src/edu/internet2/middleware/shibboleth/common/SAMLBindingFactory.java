package edu.internet2.middleware.shibboleth.common;

import org.opensaml.SAMLBinding;
import org.opensaml.SAMLSOAPBinding;

import edu.internet2.middleware.shibboleth.common.*;

/**
 *  Used by Shibboleth SHAR/AA to locate a SAML binding implementation
 *
 * @author     Scott Cantor
 * @created    April 10, 2002
 */
public class SAMLBindingFactory
{
    /**
     *  Gets a compatible binding implementation for the specified protocol and
     *  policies
     *
     * @param  protocol                          URI of SAML binding protocol
     * @param  policies                          Array of policy URIs that the
     *      implementation must support
     * @return                                   A compatible binding
     *      implementation or null if one cannot be found
     */
    public static SAMLBinding getInstance(String protocol, String[] policies)
    {
        // Current version only knows about SOAP binding and Club Shib...
        if (protocol == null || !protocol.equals(SAMLBinding.SAML_SOAP_HTTPS))
            return null;
        if (policies==null || policies.length!=1 || !policies[0].equals(Constants.POLICY_CLUBSHIB))
            return null;
        return new SAMLSOAPBinding();
    }
}

