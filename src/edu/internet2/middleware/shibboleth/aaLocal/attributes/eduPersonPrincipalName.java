import edu.internet2.middleware.eduPerson.*;
import edu.internet2.middleware.shibboleth.Constants; 
import org.opensaml.*;

public class eduPersonPrincipalName extends ScopedAttribute{
    

    public eduPersonPrincipalName(String[] scopes, Object[] values)
	throws SAMLException{

	this.super("urn:mace:eduPerson:1.0:eduPersonPrincipalName",
		   Constants.SHIB_ATTRIBUTE_NAMESPACE_URI, 
		   new QName("urn:mace:eduPerson:1.0",
			     "eduPersonPrincipalNameType"),
		   10*60,
		   values,
		   scopes[0],
		   scopes);

	if(((String)values[0]).indexOf("@") < 0)
	    super.values[0] = (String)values[0]+"@"+scopes[0];
    }
}

