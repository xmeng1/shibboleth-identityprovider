package edu.internet2.middleware.shibboleth.metadata;

import java.util.Iterator;

/**
 * @author Scott Cantor
 *
= */
public interface PDPDescriptor extends RoleDescriptor {

    public EndpointManager getAuthzServiceManager();
    
    public EndpointManager getAssertionIDRequestServiceManager();
    
    public Iterator /* <String> */ getNameIDFormats();
}
