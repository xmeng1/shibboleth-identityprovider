package edu.internet2.middleware.shibboleth.aaLocal;

/**
 *  Attribute Authority & Release Policy
 *  Simple implementation of a trivial directory layer
 *  mostly for demo and testing
 *
 * @author     Parviz Dousti (dousti@cmu.edu)
 * @created    June, 2002
 */


import java.util.*;
import javax.naming.*;
import javax.naming.directory.*;

public class EchoDirContext extends InitialDirContext{

    String uid = "unknown";
    

    public EchoDirContext(Hashtable env)
	throws NamingException{
    }

    
    public Object lookup(String s) throws NamingException{
	int i = s.indexOf("=");
	if(i >= 0)
	    uid = s.substring(i+1);
	else
	    uid = s;

	return this;
    }
    
    public Attributes getAttributes(String name, String[] ids)
	throws NamingException{

	BasicAttributes attrs = new BasicAttributes();

	for(int i=0; i<ids.length; i++){
	    if(ids[i].equalsIgnoreCase("eduPersonScopedAffiliation")){
		// return member as value;
		attrs.put(new BasicAttribute("eduPersonScopedAffiliation", "member"));
	    }
		if(ids[i].equalsIgnoreCase("eduPersonAffiliation")){
		// return member as value;
		attrs.put(new BasicAttribute("eduPersonAffiliation", "member"));
		}
	    if(ids[i].equalsIgnoreCase("eduPersonPrincipalName")){
		// return uid
		attrs.put(new BasicAttribute("eduPersonPrincipalName", uid));
	    }
		if(ids[i].equalsIgnoreCase("eduPersonEntitlement")){
		// return uid
		attrs.put(new BasicAttribute("eduPersonEntitlement", "urn:mace:example.edu:exampleEntitlement"));
		}
	}
	return attrs;
    }
}
