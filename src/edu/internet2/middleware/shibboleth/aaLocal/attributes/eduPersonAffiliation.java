package edu.internet2.middleware.shibboleth.aaLocal.attributes;


/**
 *  Attribute Authority & Release Policy
 *  A specific class for eduPersonAffiliation attribute
 *
 * @author     Parviz Dousti (dousti@cmu.edu)
 * @created    June, 2002
 */

import edu.internet2.middleware.eduPerson.*;
import edu.internet2.middleware.shibboleth.common.Constants; 
import edu.internet2.middleware.shibboleth.aa.ShibAttribute;
import org.opensaml.*;

public class eduPersonAffiliation implements ShibAttribute{
    

    public SAMLAttribute toSamlAttribute(String defaultScope, Object[] values)
	throws SAMLException{

	String[] scopes = new String[values.length];

	for(int i=0; i<values.length; i++){
	    String val = (String)values[i];
	    if(val.equalsIgnoreCase("faculty") ||
	       val.equalsIgnoreCase("student") ||
	       val.equalsIgnoreCase("staff") ||
	       val.equalsIgnoreCase("alum") ||
	       val.equalsIgnoreCase("member") ||
	       val.equalsIgnoreCase("affiliate") ||
	       val.equalsIgnoreCase("employee") )
		values[i] = val.toLowerCase();
	    else
		values[i] = "member";
	}

	return new ScopedAttribute("urn:mace:eduPerson:1.0:eduPersonAffiliation",
		   Constants.SHIB_ATTRIBUTE_NAMESPACE_URI, 
		   new QName("urn:mace:eduPerson:1.0",
			     "eduPersonAffiliationType"),
		   10*60,
		   values,
		   defaultScope,
		   scopes);
    }
}

