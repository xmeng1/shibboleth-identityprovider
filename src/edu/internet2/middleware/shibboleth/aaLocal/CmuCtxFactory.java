package edu.internet2.middleware.shibboleth.aaLocal;

/**
 *  Attribute Authority & Release Policy
 *  Directory layer for CMU specific LDAP set up
 *
 * @author     Parviz Dousti (dousti@cmu.edu)
 * @created    June, 2002
 */

import java.util.Hashtable;
import javax.naming.*;
import javax.naming.spi.*;


public class CmuCtxFactory implements InitialContextFactory{

    public Context getInitialContext(Hashtable env)
	throws NamingException{
	return new CmuDirContext(env);
    }

}
