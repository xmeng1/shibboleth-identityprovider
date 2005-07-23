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
 * SPArtifactMapper is a callback routine implementing a SAML 
 * interface. It is based on the shib-target/ArtifactMapper.cpp
 * in the C++ code and shares a lot of logic with the 
 * AttributeRequestor class with a little bit of ShibBinding thrown
 * in for good measure. This callback routine helps build and then
 * directs a request that presents an Artifact and
 * receives the Assertion that the Artifact represents.
 */
package edu.internet2.middleware.shibboleth.serviceprovider;

import java.util.Iterator;

import org.apache.log4j.Logger;
import org.opensaml.NoSuchProviderException;
import org.opensaml.ProfileException;
import org.opensaml.SAMLBinding;
import org.opensaml.SAMLBindingFactory;
import org.opensaml.SAMLException;
import org.opensaml.SAMLRequest;
import org.opensaml.SAMLResponse;
import org.opensaml.SAMLSOAPHTTPBinding;
import org.opensaml.UnsupportedExtensionException;
import org.opensaml.SAMLBrowserProfile.ArtifactMapper;
import org.opensaml.artifact.SAMLArtifact;
import org.opensaml.artifact.SAMLArtifactType0001;
import org.opensaml.artifact.SAMLArtifactType0002;

import edu.internet2.middleware.shibboleth.common.Trust;
import edu.internet2.middleware.shibboleth.metadata.Endpoint;
import edu.internet2.middleware.shibboleth.metadata.EndpointManager;
import edu.internet2.middleware.shibboleth.metadata.EntityDescriptor;
import edu.internet2.middleware.shibboleth.metadata.IDPSSODescriptor;
import edu.internet2.middleware.shibboleth.metadata.Metadata;
import edu.internet2.middleware.shibboleth.metadata.MetadataException;
import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderConfig.ApplicationInfo;

/**
 * A callback class that SAML calls when processing an Artifact.
 * The Artifact references an Assertion being held by an IdP, but 
 * SAML requires access to the Metadata and Trust services of Shibboleth
 * to locate the IdP Endpoint and generate a valid request to fetch it.
 * This class contains much in common with AttributeRequestor, but while
 * that class is static this must be an instance that captures state 
 * (mostly the ApplicationInfo block of the Application to which the
 * Artifact was directed).
 * @author Howard Gilbert
 *
 */
public class SPArtifactMapper implements ArtifactMapper {
	
	private static Logger log = Logger.getLogger(SPArtifactMapper.class.getName());
	
	// State variables set by constructor used by callback
	ApplicationInfo appinfo = null;
	ServiceProviderConfig config = null;
	

	/**
	 * To create an instance of this object you must provide a snapshot
	 * of the ServiceProviderConfig and the ApplicationInfo from the 
	 * Application element to which the Artifact is directed. We keep
	 * this around as state until they are needed by the callback.
	 * @param appinfo ApplicationInfo
	 * @param config ServiceProviderConfig
	 */
	public SPArtifactMapper(
			ApplicationInfo appinfo,
			ServiceProviderConfig config) {
		this.appinfo = appinfo;
		this.config = config;
	}


	/**
	 * The Callback routine from SAML to direct a Request containing 
	 * the Artifact to the IdP.
	 * @param request A SAMLRequest to resolve the Artifact
	 * @return The SAMLResponse from the IdP
	 * @throws SAMLException
	 */
	public SAMLResponse resolve(SAMLRequest request) 
		throws SAMLException {
		SAMLResponse response = null;
		
		// Ok, so what is this Artifact anyway
		Iterator artifacts = request.getArtifacts();
		if (!artifacts.hasNext())
			throw new SAMLException("SPArtifactMapper was passed no artifact.");
		EntityDescriptor entity = null;
		SAMLArtifact artifact = null;
		while (artifacts.hasNext()) {
			artifact = (SAMLArtifact)artifacts.next();
			entity = ((Metadata)appinfo).lookup(artifact);
			if (entity!=null)
				break;
		}
		if (entity==null) {
			throw new MetadataException("Unable to find Artifact issuer in Metadata.");
		}
		String entityId = entity.getId();
		log.info("Processing Artifact issued by "+entityId);

        IDPSSODescriptor idp = entity.getIDPSSODescriptor(
                request.getMinorVersion()==1?
                    org.opensaml.XML.SAML11_PROTOCOL_ENUM :
                    org.opensaml.XML.SAML10_PROTOCOL_ENUM
                );
        if (idp==null) {
        	throw new MetadataException("Entity "+entityId+" has no usable IDPSSODescriptor.");
        }
		
		
		// Sign the Request if so configured
        String credentialId = appinfo.getCredentialIdForEntity(entity);
        if (credentialId!=null)
            AttributeRequestor.possiblySignRequest(config.getCredentials(), request, credentialId);
        
        //TODO: C++ code determines if the IdP is authenticated
        //boolean authenticated=false; 
        
        if (artifact instanceof SAMLArtifactType0001) {
        	// A Type1 Artifact takes any usable SOAP Endpoint
            EndpointManager endpointManager = idp.getArtifactResolutionServiceManager();
            Iterator endpoints = endpointManager.getEndpoints();
            while (endpoints.hasNext()) {
                //  Search for an Endpoint with a SOAP Binding
            	Endpoint endpoint = (Endpoint)endpoints.next();
            	String binding = endpoint.getBinding();
            	if (!binding.equals(SAMLBinding.SOAP))
            		continue; // The C++ code is more elaborate here
                
            	response = resolveArtifact(request, idp, endpoint);
                break; // Got response, stop scanning endpoints
            }
        } else if (artifact instanceof SAMLArtifactType0002) {
            // A Type2 Artifact carries an Endpoint location
        	SAMLArtifactType0002 type2 = (SAMLArtifactType0002) artifact;
            EndpointManager endpointManager = idp.getArtifactResolutionServiceManager();
            Iterator endpoints = endpointManager.getEndpoints();
            while (endpoints.hasNext()) {
                // Search for an Endpoint matching the Artifact
            	Endpoint endpoint = (Endpoint)endpoints.next();
            	String binding = endpoint.getBinding();
            	if (!binding.equals(SAMLBinding.SOAP))
            		continue; // The C++ code is more elaborate here
            	String location = endpoint.getLocation();
            	if (!location.equals(type2.getSourceLocation()))
            		continue;
                
            	response = resolveArtifact(request, idp, endpoint);
                break; // Got response, stop scanning endpoints
            }
        } else {
        	throw new UnsupportedExtensionException("Unrecognized Artifact type.");
        }
        if (response == null) {
            throw new MetadataException("Unable to locate acceptable binding/endpoint to resolve artifact.");
        }
        return response;
	}

	/**
     * Call back into SAML to transmit the Request to the IdP Enpoint
     * and get back the Response represented by the Artifact.
     * @param request A SAMLRequest containing the Artifact
     * @param idp The IdP entity
     * @param endpoint The IdP Endpoint
     * @return The SAMLResponse returned by the IdP
     * @throws NoSuchProviderException
     * @throws SAMLException
     * @throws ProfileException if the response has no assertions
	 */
    private SAMLResponse resolveArtifact(SAMLRequest request, IDPSSODescriptor idp, Endpoint endpoint) throws NoSuchProviderException, SAMLException, ProfileException {
        SAMLResponse response;
        SAMLBinding sbinding = SAMLBindingFactory.getInstance(endpoint.getBinding());            	
        if (sbinding instanceof SAMLSOAPHTTPBinding) { // I shure hope so
            SAMLSOAPHTTPBinding httpbind = (SAMLSOAPHTTPBinding)sbinding;
            httpbind.addHook(new ShibHttpHook(idp,(Trust)appinfo));
        }
        response=sbinding.send(endpoint.getLocation(),request);
        if (!response.getAssertions().hasNext()) {
        	throw new ProfileException("No SAML assertions returned in response to artifact profile request.");
        }
        return response;
    }

}
