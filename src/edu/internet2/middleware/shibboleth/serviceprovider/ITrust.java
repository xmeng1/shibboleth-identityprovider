/*
 * ITrust.java [Sorry but Trust.java is a very popular class name]
 * 
 * Trust provider plugins obtain keys and certificates from the configuration
 * file and then provide the logic to validate signatures.
 * 
 * Corresponds to ITrust interface of the C++ code. 
 * 
 * A pluggable trust element in a Shibboleth configuration
 * file builds or gains access to a collection of keys and/or
 * certificates (that contain keys). Each key/certificate is 
 * associated with one or more subject names that represent
 * Shibboleth services at a particular institution (Entity). 
 * 
 * The function of Trust is to determine the Subject name
 * from the SAMLAssertion, look up the key/certificate for
 * that Subject, apply a wildcard where appropriate, and then
 * ask OpenSAML to ask XML Security to validate the assertion
 * given the key.
 * 
 * Notably implemented by XMLTrustImpl.
 * 
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

import java.util.Iterator;

import org.opensaml.SAMLObject;

import edu.internet2.middleware.shibboleth.metadata.Metadata;
import edu.internet2.middleware.shibboleth.metadata.RoleDescriptor;

/**
 * @author Howard Gilbert
 */
public interface ITrust {
	
	/**
	 * Validate a signed SAML object using configuration data
	 * 
	 * @param revocations Revocation Providers from the &lt;Application&gt;
	 * @param role        The Role [HS, SHAR] from the Entity 
	 * @param token       The signed SAML object
	 * @param locator     ApplicationInfo[.getEntityDescriptor(String id), was IMetadata]
	 * @return            true if the object validates
	 */
	boolean validate(
		Iterator revocations,
		RoleDescriptor role,
		SAMLObject token,
		Metadata locator
	);
	
	/*
	 * Note: Java attach() has no implementations or uses at this point
	 */
	boolean attach (
		Iterator revocations,
		RoleDescriptor role
	);

}
