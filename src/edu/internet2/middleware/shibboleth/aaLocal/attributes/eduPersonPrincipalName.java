package edu.internet2.middleware.shibboleth.aaLocal.attributes;


/**
 *  Attribute Authority & Release Policy
 *  A specific class for EPPN
 *
 * @author     Parviz Dousti (dousti@cmu.edu)
 * @created    June, 2002
 */

import java.util.Collections;

import edu.internet2.middleware.eduPerson.*;
import edu.internet2.middleware.shibboleth.common.Constants; 
import edu.internet2.middleware.shibboleth.aa.ShibAttribute;

import org.apache.log4j.Logger;
import org.opensaml.*;

public class eduPersonPrincipalName implements ShibAttribute{
	
	private static Logger log = Logger.getLogger(eduPersonPrincipalName.class.getName());
    

    public SAMLAttribute toSamlAttribute(String defaultScope, Object[] values, String recipient)
	throws SAMLException{

	String scope = null;
	String val = null;
	String eppn = (String)values[0];

	int x = eppn.indexOf("@") ;
	log.debug("EPPN: "+eppn+"    @ at "+x);
	if(x > 0){
	    val = eppn.substring(0,x);
	    scope = eppn.substring(x+1);
	}else{
	    val = eppn;
	    scope = defaultScope;
	}

	log.debug("Sending value=" + val + ", scope=" + scope);
		
	return new ScopedAttribute("urn:mace:eduPerson:1.0:eduPersonPrincipalName",
				 Constants.SHIB_ATTRIBUTE_NAMESPACE_URI, 
                 defaultScope,
				 null,
				 10*60,
                 Collections.singleton(scope),
				 Collections.singleton(val));

    }

}

