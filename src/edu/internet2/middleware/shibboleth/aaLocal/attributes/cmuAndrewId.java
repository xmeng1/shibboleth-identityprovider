package edu.internet2.middleware.shibboleth.aaLocal.attributes;

import edu.internet2.middleware.eduPerson.*;
import edu.internet2.middleware.shibboleth.common.Constants; 
import org.opensaml.*;


public class cmuAndrewId extends ScopedAttribute{
    

    public cmuAndrewId(String[] scopes, Object[] values)
	throws SAMLException{

	super("urn:mace:eduPerson:1.0:eduPersonPrincipalName",
		   Constants.SHIB_ATTRIBUTE_NAMESPACE_URI, 
		   new QName("urn:mace:eduPerson:1.0",
			     "eduPersonPrincipalNameType"),
		   10*60,
		   values,
		   scopes[0],
		   scopes);
    }
}

