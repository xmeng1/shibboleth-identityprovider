import edu.internet2.middleware.eduPerson.*;
import edu.internet2.middleware.shibboleth.common.Constants; 
import edu.internet2.middleware.shibboleth.aa.ShibAttribute;
import org.opensaml.*;

public class eduPersonPrincipalName implements ShibAttribute{
    

    public SAMLAttribute toSamlAttribute(String defaultScope, Object[] values)
	throws SAMLException{

	String scopes[] = new String[1];
	String vals[] = new String[1];
	String eppn = (String)values[0];

	int x = eppn.indexOf("@") ;
	System.out.println("EPPN: "+eppn+"    @ at "+x);
	if(x > 0){
	    vals[0] = eppn.substring(0,x);
	    scopes[0] = eppn.substring(x+1);
	}else{
	    vals[0] = eppn;
	    scopes[0] = defaultScope;
	}

	System.out.println("AA debug: sending value="+vals[0]+"  scope="+scopes[0]);
		
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

