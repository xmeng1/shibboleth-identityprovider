/*
 * AAP.java
 * 
 * Interface presented by an AAP provider. 
 * Corresponds to IAAP in C++ shib.h
 * 
 * Notably implemented by ...target.XMLAAPImpl
 */
package edu.internet2.middleware.shibboleth.common;

/**
 * @author Howard Gilbert
 */
public interface AAP {
	
	boolean isAnyAttribute();
	AttributeRule lookup(String attrName, String attrNamespace);
	AttributeRule lookup(String alias);
	AttributeRule[] getAttributeRules();

}
