/*
 * EntityLocator.java
  */
package edu.internet2.middleware.shibboleth.metadata;

/**
 * @author Howard Gilbert
 */
public interface EntityLocator extends Metadata {
	
	EntityDescriptor getEntityDescriptor(String id);

}
