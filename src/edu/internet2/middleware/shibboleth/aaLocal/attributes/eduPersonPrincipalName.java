package edu.internet2.middleware.shibboleth.aaLocal.attributes;


/**
 *  Attribute Authority & Release Policy
 *  A specific class for EPPN
 *
 * @author     Parviz Dousti (dousti@cmu.edu)
 * @created    June, 2002
 */

import edu.internet2.middleware.eduPerson.*;
import edu.internet2.middleware.shibboleth.common.Constants; 
import edu.internet2.middleware.shibboleth.aa.ShibAttribute;

import org.apache.log4j.Logger;
import org.opensaml.*;

public class eduPersonPrincipalName implements ShibAttribute{
	
	private static Logger log = Logger.getLogger(eduPersonPrincipalName.class.getName());
    

    public SAMLAttribute toSamlAttribute(String defaultScope, Object[] values)
	throws SAMLException{

	String scopes[] = new String[1];
	String vals[] = new String[1];
	String eppn = (String)values[0];

	int x = eppn.indexOf("@") ;
	log.debug("EPPN: "+eppn+"    @ at "+x);
	if(x > 0){
	    vals[0] = eppn.substring(0,x);
	    scopes[0] = eppn.substring(x+1);
	}else{
	    vals[0] = eppn;
	    scopes[0] = defaultScope;
	}

	log.debug("Sending value="+vals[0]+"  scope="+scopes[0]);
		
	return new ScopedAttribute("urn:mace:eduPerson:1.0:eduPersonPrincipalName",
				 Constants.SHIB_ATTRIBUTE_NAMESPACE_URI, 
				 new QName("urn:mace:eduPerson:1.0",
					   "eduPersonPrincipalNameType"),
				 10*60,
				 vals,
				 defaultScope,
				 scopes);

    }

}

