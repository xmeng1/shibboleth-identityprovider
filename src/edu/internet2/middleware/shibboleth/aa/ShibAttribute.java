package edu.internet2.middleware.shibboleth.aa;

import org.opensaml.*;

public interface ShibAttribute{
    
    public SAMLAttribute toSamlAttribute(String defaultScope, Object[] values)
	throws SAMLException;

}

