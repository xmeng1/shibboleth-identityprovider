package edu.internet2.middleware.shibboleth.aa;

/**
 *  Attribute Authority & Release Policy
 *  a Common interface among all attributes that are released by AA
 *
 * @author     Parviz Dousti (dousti@cmu.edu)
 * @created    June, 2002
 */


import org.opensaml.*;

public interface ShibAttribute{
    
    public SAMLAttribute toSamlAttribute(String defaultScope, Object[] values)
	throws SAMLException;

}

