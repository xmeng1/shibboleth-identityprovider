/*
 * AttributeAuthorityRole.java
  */
package edu.internet2.middleware.shibboleth.metadata;

import org.opensaml.SAMLAttributeDesignator;

/**
 * @author Howard Gilbert
 */
public interface AttributeAuthorityRole extends ProviderRole {
	
	Endpoint[] getAttributeServices();
	SAMLAttributeDesignator[] getAttributeDesignators();

}
