import java.util.*;
import javax.naming.*;
import javax.naming.directory.*;

public class CmuDirContext extends InitialDirContext{

    DirContext ctx; 

    public CmuDirContext(Hashtable env)
	throws NamingException{

	Hashtable env1 = new Hashtable(11);
	env1.put(Context.INITIAL_CONTEXT_FACTORY,
	       "com.sun.jndi.ldap.LdapCtxFactory");

	env1.put(Context.PROVIDER_URL, env.get(Context.PROVIDER_URL));
	ctx = new InitialDirContext(env1);
    }

    
    public Object lookup(String s) throws NamingException{
	String uid = null;

	int i = s.indexOf("=");
	if(i >= 0)
	    uid = s.substring(i+1);
	else
	    uid = s;

	NamingEnumeration ne = ctx.search("", "cmuAndrewId="+uid, null, null);

	if(ne != null && ne.hasMoreElements()){
	    SearchResult rs = (SearchResult)ne.nextElement();
	    String guid = (String)rs.getAttributes().get("GUID").get();
	    return ctx.lookup("guid="+guid);
	}
	return null;
    }
    
    public Attributes getAttributes(String name, String[] ids)
	throws NamingException{
	return ctx.getAttributes(name, ids);
    }
}
