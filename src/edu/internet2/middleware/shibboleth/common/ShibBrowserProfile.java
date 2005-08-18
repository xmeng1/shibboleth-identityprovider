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

package edu.internet2.middleware.shibboleth.common;

import java.util.ArrayList;

import org.apache.log4j.Logger;
import org.opensaml.NoSuchProviderException;
import org.opensaml.ReplayCache;
import org.opensaml.SAMLBrowserProfile;
import org.opensaml.SAMLBrowserProfileFactory;
import org.opensaml.SAMLException;
import org.opensaml.TrustException;
import org.opensaml.SAMLBrowserProfile.ArtifactMapper;
import org.opensaml.SAMLBrowserProfile.BrowserProfileRequest;
import org.opensaml.SAMLBrowserProfile.BrowserProfileResponse;

import edu.internet2.middleware.shibboleth.metadata.EntityDescriptor;
import edu.internet2.middleware.shibboleth.metadata.IDPSSODescriptor;
import edu.internet2.middleware.shibboleth.metadata.MetadataException;
import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderConfig;
import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderContext;
import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderConfig.ApplicationInfo;

/**
 * Basic Shibboleth POST browser profile implementation with basic support for signing
 * 
 * @author Scott Cantor @created April 11, 2002
 */
public class ShibBrowserProfile  {

	private static Logger	log			= Logger.getLogger(ShibBrowserProfile.class.getName());

    /** Policy URIs to attach or check against */
    protected ArrayList     policies    = new ArrayList();

    protected SAMLBrowserProfile profile = SAMLBrowserProfileFactory.getInstance(); 
    private static ServiceProviderContext context = ServiceProviderContext.getInstance();
    private String applicationId = null;
    
    /**
     * Identify the <Application> from which to get plugins.
     * 
     * @param applicationId 
     */
    public ShibBrowserProfile(String applicationId) throws NoSuchProviderException {
        this.applicationId = applicationId;
    }


    /**
     * @see org.opensaml.SAMLBrowserProfile#receive(java.lang.StringBuffer, javax.servlet.http.HttpServletRequest, java.lang.String, int, org.opensaml.ReplayCache, org.opensaml.SAMLBrowserProfile.ArtifactMapper, int)
     */
    public BrowserProfileResponse receive(
            StringBuffer issuer,
            BrowserProfileRequest bpRequest,
            String recipient,
            ReplayCache replayCache,
            ArtifactMapper artifactMapper,
            int minorVersion
            ) throws SAMLException {
        
        String providerId = null;
        issuer.setLength(0);
        
        // Let SAML do all the decoding and parsing
        BrowserProfileResponse bpr = profile.receive(issuer, bpRequest, recipient, replayCache, artifactMapper, minorVersion);
        
        /*
         * Now find the Metadata for the Entity that send this assertion.
         * From the C++, look first for issuer, then namequalifier (for 1.1 compat.)
         */
        EntityDescriptor entity = null;
        String asn_issuer = bpr.assertion.getIssuer();
        String qualifier = bpr.authnStatement.getSubject().getNameIdentifier().getNameQualifier();
        ServiceProviderConfig config = context.getServiceProviderConfig();
        ApplicationInfo appinfo = config.getApplication(applicationId);
        
        entity = appinfo.lookup(asn_issuer);
        providerId=asn_issuer;
        if (entity==null) {
            providerId=qualifier;
            entity= appinfo.lookup(qualifier);
        }
        if (entity==null) {
            log.error("assertion issuer not found in metadata(Issuer ="+
                    issuer+", NameQualifier="+qualifier);
            throw new MetadataException("ShibBrowserProfile.receive() metadata lookup failed, unable to process assertion");
        }
        issuer.append(providerId);
        
        IDPSSODescriptor role = entity.getIDPSSODescriptor(
                minorVersion==1?
                    org.opensaml.XML.SAML11_PROTOCOL_ENUM :
                    org.opensaml.XML.SAML10_PROTOCOL_ENUM
                );
        
        if (bpr.response.isSigned()) {
            boolean signatureValid = appinfo.validate(bpr.response,role);
            if (!signatureValid) {
                throw new TrustException("ShibBrowserProfile cannot validate signature on response from SSO");
            }
        }
        if (bpr.assertion.isSigned()) {
            boolean signatureValid = appinfo.validate(bpr.assertion,role);
            if (!signatureValid) {
                throw new TrustException("ShibBrowserProfile cannot validate signature on assertion from SSO");
            }
        }
        
        return bpr;
    }
}
