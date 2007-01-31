/*
 * Copyright [2006] [University Corporation for Advanced Internet Development, Inc.]
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
package edu.internet2.middleware.shibboleth.idp.profile.saml2;

import java.io.InputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.List;


import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import edu.internet2.middleware.shibboleth.common.profile.ProfileHandler;
import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationManager;

import javolution.util.FastList;

import org.apache.log4j.Logger;

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.ParserPoolManager;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextDeclRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.GetComplete;
import org.opensaml.saml2.core.IDPEntry;
import org.opensaml.saml2.core.IDPList;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.Scoping;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.XMLParserException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.xml.sax.InputSource;


/**
 * SAML 2.0 Authentication Request profile handler
 */
public class AuthenticationRequest implements ProfileHandler {
    
    private static final Logger log =
            Logger.getLogger(AuthenticationRequest.class.getName());
    
    
    /** AuthenticationManager to be used */
    private AuthenticationManager authnMgr;
    
    
    /** {@inheritDoc} */
    public boolean processRequest(ServletRequest request, ServletResponse response) throws ServletException {
        
    
//        // Check if we are in scope to handle this AuthnRequest
//        // XXX: How do we get the current IdP's relying party uri (if we're in multiple feds?)
//        boolean scopeOK = this.checkScope(authnRequest, "");
//        if (!scopeOK) {
//            log.error("AuthnRequest contains a Scoping element which "
//                    + "does not contain a providerID registered with this IdP.");
//        }
	
	
        return false;
    }

    
    /**
     * Check if an {@link AuthnRequest} contains a {@link Scoping} element.
     * If so, check if the specified IdP is in the {@link IDPList} element.
     * If no Scoping element is present, this method returns <code>true</code>.
     *
     * @param authnRequest The {@link AuthnRequest} element to check.
     * @param providerId The IdP's ProviderID
     *
     * @return <code>true</code>if idp is in the IDPList, otherwise <code>false</code>
     */
    private boolean checkScope(final AuthnRequest authnRequest, String providerId) {
        
        List<String> idpEntries = new FastList<String>();
        
        if (authnRequest == null) {
            return (false);
        }
        
        if (providerId == null) {
            return (false);
        }
        
        Scoping scoping = authnRequest.getScoping();
        if (scoping == null) {
            return (true);
        }
        
        // process all of the explicitly listed idp provider ids
        IDPList idpList = scoping.getIDPList();
        if (idpList == null) {
            return (true);
        }
        
        List<IDPEntry> explicitIDPEntries = idpList.getIDPEntrys();
        if (explicitIDPEntries != null) {
            for (IDPEntry entry : explicitIDPEntries) {
                String s = entry.getProviderID();
                if (s != null) {
                    idpEntries.add(s);
                }
            }
        }
        
        
        // If the IDPList is incomplete, retrieve the complete list
        // and add the entries to idpEntries.
        GetComplete getComplete = idpList.getGetComplete();
        IDPList referencedIdPs = this.getCompleteIDPList(getComplete);
        if (referencedIdPs != null) {
            List<IDPEntry> referencedIDPEntries = referencedIdPs.getIDPEntrys();
            if (referencedIDPEntries != null) {
                for (IDPEntry entry : referencedIDPEntries) {
                    String s = entry.getProviderID();
                    if (s != null) {
                        idpEntries.add(s);
                    }
                }
            }
        }
        
        
        // iterate over all the IDPEntries we've gathered, 
        // and check if we're in scope.
        boolean found = false;
        for (String requestProviderId : idpEntries) {
            if (providerId.equals(requestProviderId)) {
                found = true;
                log.debug("Found Scoping match for IdP: (" 
                            + providerId + ")");
                break;
            }
        }
        
        return (found);
    }

    
    /**
     * Retrieve an incomplete IDPlist.
     *
     * This only handles URL-based <GetComplete/> references.
     *
     * @param getComplete The (possibly <code>null</code>) &lt;GetComplete/&gt; element
     *
     * @return an {@link IDPList} or <code>null</code> if the uri can't be dereferenced.
     */
    private IDPList getCompleteIDPList(GetComplete getComplete) {
        
        // XXX: enhance this method to cache the url and last-modified-header
        
        if (getComplete == null) {
            return (null);
        }
        
        String uri = getComplete.getGetComplete();
        if (uri != null) {
            return (null);
        }
        
        
        IDPList idpList = null;
        InputStream istream = null;
        
        try {
            URL url = new URL(uri);
            URLConnection conn = url.openConnection();
            istream = conn.getInputStream();
            
            // convert the raw data into an XML object
            DefaultBootstrap.bootstrap();
            ParserPoolManager parserMgr = ParserPoolManager.getInstance();
            Document doc = parserMgr.parse(new InputSource(istream));
            Element docElement = doc.getDocumentElement();
            Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(docElement);
            idpList = (IDPList) unmarshaller.unmarshall(docElement);
            
        } catch (MalformedURLException ex) {
            log.error("Unable to retrieve GetComplete IDPList. Unsupported URI: " + uri);
        } catch (IOException ex) {
            log.error("IO Error while retreieving GetComplete IDPList from " + uri, ex);
        } catch (ConfigurationException ex) {
            log.error("Internal OpenSAML error while parsing GetComplete IDPList from " + uri, ex);
        } catch (XMLParserException ex) {
            log.error("Internal OpenSAML error while parsing GetComplete IDPList from " + uri, ex);
        } catch (UnmarshallingException ex) {
            log.error("Internal OpenSAML error while unmarshalling GetComplete IDPList from " + uri, ex);
        } finally {
            if (istream != null) {
                try {
                    istream.close();
                } catch (IOException ex) {
                    // nothing to do here.
                }
            }
        }
        
        return idpList;
    }
}
