/*
 * AttributeRule.java
 * 
 * Interface to apply AAP, based on IAttributeRule in C++ shib.h
 * 
 * Notably implemented by XMLAttributeRuleImpl in ...target.XMLAAPImpl
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
package edu.internet2.middleware.shibboleth.common;

import org.opensaml.SAMLAttribute;

import edu.internet2.middleware.shibboleth.metadata.EntityDescriptor;

/**
 * @author Howard Gilbert
 */
public interface AttributeRule {
	String getName();
	String getNamespace();
	String getAlias();
	String getHeader();
	
	void apply(EntityDescriptor originSite, SAMLAttribute attribute);

}
