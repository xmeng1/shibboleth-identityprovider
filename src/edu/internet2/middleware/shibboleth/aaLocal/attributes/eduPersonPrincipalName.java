import edu.internet2.middleware.eduPerson.*;
import edu.internet2.middleware.shibboleth.common.Constants; 
import edu.internet2.middleware.shibboleth.aa.ShibAttribute;
import org.opensaml.*;

public class eduPersonPrincipalName implements ShibAttribute{
    

    public SAMLAttribute toSamlAttribute(String defaultScope, Object[] values)
	throws SAMLException{

	String scopes[] = new String[1];

	int x = ((String)values[0]).indexOf("@") ;
	int len = ((String)values[0]).length();
	if(x > 0){
	    values[0] = ((String)values[0]).substring(0,x-1);
	    scopes[0] = ((String)values[0]).substring(x+1, len);
	}	
	return new ScopedAttribute("urn:mace:eduPerson:1.0:eduPersonPrincipalName",
				 Constants.SHIB_ATTRIBUTE_NAMESPACE_URI, 
				 new QName("urn:mace:eduPerson:1.0",
					   "eduPersonPrincipalNameType"),
				 10*60,
				 values,
				 defaultScope,
				 scopes);

    }

}

