package edu.internet2.middleware.shibboleth.common;

import java.security.Key;
import java.security.KeyStore;
import java.util.Iterator;

/**
 *  Used by a Shibboleth SHIRE implementation to validate origin site
 *  information and locate signature verification keys when validating responses
 *  and assertions from a Handle Service<P>
 *
 *  The interface MUST be thread-safe.
 *
 * @author     Scott Cantor
 * @created    January 24, 2002
 */
public interface OriginSiteMapper
{
    /**
     *  Provides an iterator over the trusted Handle Services for the specified
     *  origin site
     *
     * @param  originSite  The DNS name of the origin site to query
     * @return             An iterator over the Handle Service DNS names
     */
    public abstract Iterator getHandleServiceNames(String originSite);

    /**
     *  Returns a preconfigured key to use in verifying a signature created by
     *  the specified HS<P>
     *
     *  Any key returned is implicitly trusted and a certificate signed by
     *  another trusted entity is not sought or required
     *
     * @param  handleService  Description of Parameter
     * @return                A trusted key (probably public but could be
     *      secret) or null
     */
    public abstract Key getHandleServiceKey(String handleService);

    /**
     *  Provides an iterator over the security domain expressions for which the
     *  specified origin site is considered to be authoritative
     *
     * @param  originSite  The DNS name of the origin site to query
     * @return             An iterator over a set of regular expression strings
     */
    public abstract Iterator getSecurityDomains(String originSite);

    /**
     *  Gets a key store containing certificate entries that are trusted to sign
     *  Handle Service certificates that are encountered during processing<P>
     *
     *
     *
     * @return    A key store containing trusted certificate issuers
     */
    public abstract KeyStore getTrustedRoots();
}

