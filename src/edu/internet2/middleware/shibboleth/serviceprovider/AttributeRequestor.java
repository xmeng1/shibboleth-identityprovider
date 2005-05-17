/*
 * AttributeRequestor.java
 * 
 * Generate a SAMLRequest to the AA for Attributes, then process the
 * reply. In C++, this logic was InternalCCacheEntry::getNewResponse() 
 * in shib-ccache.cpp.
 * 
 * The User Authentication was previously processed by ShibPOSTProfile
 * and was stored by SessionManager in a Session object. Although the
 * attributes might be fetched immediately, that is a strategy issue.
 * In Java, we isolate the Attribute fetch in this separate module.
 * 
 * The Session block retains a copy of the original SAMLStatement from
 * the POST, and it contains information about the remote Entity.
 * However, the POST came from the HS (or IIDPProvider if you want to
 * use SAML 2 terms), and this transaction has to go to the AA. So
 * Metadata must be used to obtain the AttributeAuthorityRole and its
 * associated Endpoint (URL).
 * 
 * The ApplicationInfo object for the configured Application presents
 * a getAttributeDesignators method that can return a list of attributes
 * to specify in the request. However, I can find no configuration element
 * that corresponds to this, and no example logic. For now that method
 * returns an empty collection and no particular attributes are requested.
 * 
 * The actual SSL session and exchange of data is performed by OpenSAML.
 * Our interface to SAML is through the separate ShibBind module. The
 * layers of processing and responsibilites need to be understood.
 * 
 * ShibBind uses the Metadata for the User's ID Providing Entity to
 * locate the AttributeAuthorityRole and therefore the AA URL. This
 * is passed to OpenSAML along with the request. Upon return, if any
 * statements are signed it is the responsiblilty of ShibBind to call
 * the Trust implementations to validate the signatures.
 * 
 * This module then checks, by calling the isSigned() property of
 * SAMLObjects, to make sure that everything that is supposed to be
 * signed actually was signed. ShibBind knows if a signature is valid,
 * but this module knows if a signature was requred. This module also
 * applies AAP to examine attributes and values and discard those that
 * the policy doesn't accept.
 * 
 * Recovery Context: All exceptions handled and logged internally.
 * --------------------
 * Copyright 2002, 2004 
 * University Corporation for Advanced Internet Development, Inc. 
 * All rights reserved
 * [Thats all we have to say to protect ourselves]
 * Your permission to use this code is governed by "The Shibboleth License".
 * A copy may be found at http://shibboleth.internet2.edu/license.html
 * [Nothing in copyright law requires license text in every file.]
 */
package edu.internet2.middleware.shibboleth.serviceprovider;

import java.util.Collection;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAttributeQuery;
import org.opensaml.SAMLAuthenticationStatement;
import org.opensaml.SAMLException;
import org.opensaml.SAMLRequest;
import org.opensaml.SAMLResponse;
import org.opensaml.SAMLSubject;
import org.opensaml.XML;

import x0.maceShibbolethTargetConfig1.ApplicationDocument.Application;

import edu.internet2.middleware.shibboleth.metadata.AttributeAuthorityDescriptor;
import edu.internet2.middleware.shibboleth.metadata.EntityDescriptor;
import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderConfig.ApplicationInfo;

/**
 * A static class with a static method. No objects are created
 * 
 * @author Howard Gilbert
 */
public class AttributeRequestor {
	
	private static Logger log = Logger.getLogger(AttributeRequestor.class);
	private static ServiceProviderContext context   = ServiceProviderContext.getInstance();
	
	private AttributeRequestor() {} // Prevent instantiation
	
	/**
	 * Request SAML Attribute response from AA
	 * 
	 * @param session Session object (from authentication POST)
	 * @return true if Attributes successfully stored in the Session
	 * @throws MetadataException If IdP has no configured AA
	 * @throws SAMLException If there is a problem with the reply
	 */
	static 
			boolean    // return false if attributes are not fetched
	fetchAttributes(
			Session session){
		
	    log.debug("Fetching attributes for session "+session.getKey()+
	            " from "+session.getEntityId());
	    
		// Get local references to configuration objects
		ServiceProviderConfig config = context.getServiceProviderConfig();
		ApplicationInfo appinfo = config.getApplication(session.getApplicationId());
		
		// The Entity name was fed by by ShibPOSTProfile.accept(). Look it up now.
		EntityDescriptor entity = appinfo.lookup(session.getEntityId());
		if (entity==null) {
			log.error("Entity(Site) deleted from Metadata since authentication POST received: "+session.getEntityId());
			return false;
		}
		Application applicationConfig = appinfo.getApplicationConfig();
		
		SAMLRequest request = null;
		
		AttributeAuthorityDescriptor aa = 
		    entity.getAttributeAuthorityDescriptor(XML.SAML11_PROTOCOL_ENUM); // throws MetadataException
		if (aa==null) {
		    log.error("No Attribute Authority in Metadata for ID="+entity.getId());
		    return false;
		}
		
		// Build the Attribute Query 
		SAMLAttributeQuery query = null;
		SAMLSubject subject;
		try {
			SAMLAuthenticationStatement authenticationStatement = session.getAuthenticationStatement();
			if (authenticationStatement==null) {
			    log.error("Session contains no Authentication Statement." );
			    return false;
			}
			SAMLSubject subject2 = authenticationStatement.getSubject();
			if (subject2==null) {
			    log.error("Session Authentication Statement contains no Subject." );
			    return false;
			}
			subject = (SAMLSubject) subject2.clone();
		} catch (Exception e) {
		    log.error("Unable to generate the query SAMLSubject from the Authenticaiton." );
		    return false;
		}
		log.debug("Subject (Handle) is "+subject.getNameIdentifier());
		Collection attributeDesignators = appinfo.getAttributeDesignators();
		try {
            query = 
                new SAMLAttributeQuery(
            		subject,     		 // Subject (i.e. Handle) from authentication
            		appinfo.getProviderId(),  // SP Entity name
            		attributeDesignators // Attributes to request, null for everything
            		);

            // Wrap the Query in a request
            request = new SAMLRequest(query);
        } catch (SAMLException e) {
            log.error("AttributeRequestor unable to build SAML Query for Session "+session.getKey());
            return false;
        }
		
		
		// ShibBinding will extract URLs from the Metadata and build
		// parameters so SAML can create the session. It also interfaces
		// to Trust to verify that any signed objects have trusted signatures.
		SAMLResponse response = null;
		try {
            ShibBinding binding = new ShibBinding(session.getApplicationId());
			response = binding.send(request,aa,null,null);
		} catch (SAMLException e) {;} // response will be null
		if (response==null) {
			log.error("AttributeRequestor Query to remote AA returned no response from "+session.getEntityId());
			return false;
		}
		
		
		// Check each assertion in the response.
        int acount = 0;
		Iterator assertions = response.getAssertions();
		while (assertions.hasNext()) {
			SAMLAssertion assertion = (SAMLAssertion) assertions.next();
//			if (signedAssertions && !assertion.isSigned()) {
//			        log.warn("AttributeRequestor has removed unsigned assertion from response from "+session.getEntityId());
//				response.removeAssertion(acount);
//				continue;
//			}
			
            try {
                appinfo.applyAAP(assertion,aa); // apply each AAP to this assertion
                acount++;
            }
			catch (SAMLException ex) {
                response.removeAssertion(acount); // AAP rejected all statements for this assertion
            }
		}

		// A response may end up with no attributes, but that is not an error.
		// Maybe there is just nothing important to say about this user.
		
		session.setAttributeResponse(response); // Save response in Session object
		return true;
	}

}
