import edu.internet2.middleware.eduPerson.*;
import edu.internet2.middleware.shibboleth.common.Constants; 
import org.opensaml.*;

public class eduPersonAffiliation extends ScopedAttribute{
    

    public eduPersonAffiliation(String[] scopes, Object[] values)
	throws SAMLException{

	super("urn:mace:eduPerson:1.0:eduPersonAffiliation",
		   Constants.SHIB_ATTRIBUTE_NAMESPACE_URI, 
		   new QName("urn:mace:eduPerson:1.0",
			     "eduPersonAffiliationType"),
		   10*60,
		   values,
		   scopes[0],
		   scopes);

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

    }
}

