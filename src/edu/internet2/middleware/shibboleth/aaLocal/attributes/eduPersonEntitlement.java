
/**
 *  Attribute Authority & Release Policy
 *  A specific class for eduPersonEntitlement attribute
 *
 * @author     Parviz Dousti (dousti@cmu.edu)
 * @created    June, 2002
 */

import edu.internet2.middleware.eduPerson.*;
import edu.internet2.middleware.shibboleth.common.Constants; 
import edu.internet2.middleware.shibboleth.aa.ShibAttribute;
import org.opensaml.*;

public class eduPersonEntitlement implements ShibAttribute{
    

    public SAMLAttribute toSamlAttribute(String defaultScope, Object[] values)
	throws SAMLException{

	return new SAMLAttribute("urn:mace:eduPerson:1.0:eduPersonEntitlement",
		   Constants.SHIB_ATTRIBUTE_NAMESPACE_URI, 
		   new QName("urn:mace:eduPerson:1.0",
			     "xsd:anyURI"),
				 10*60,
				 values);

    }
}

