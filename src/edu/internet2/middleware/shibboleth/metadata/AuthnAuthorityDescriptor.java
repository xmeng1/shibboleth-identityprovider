package edu.internet2.middleware.shibboleth.metadata;

import java.util.Iterator;

/**
 * @author Scott Cantor
 *
= */
public interface AuthnAuthorityDescriptor extends RoleDescriptor {

    public EndpointManager getAuthnQueryServiceManager();
    
    public EndpointManager getAssertionIDRequestServiceManager();
    
    public Iterator /* <String> */ getNameIDFormats();
}
