package edu.internet2.middleware.shibboleth.aaLocal;

/**
 *  Attribute Authority & Release Policy
 *  Demonstration of how a SQL impl. of directory layer
 *  might work.
 *
 * @author     Parviz Dousti (dousti@cmu.edu)
 * @created    June, 2002
 */


import java.util.Hashtable;
import javax.naming.*;
import javax.naming.spi.*;


public class SQLCtxFactory implements InitialContextFactory{

    public Context getInitialContext(Hashtable env)
	throws NamingException{
	return new SQLDirContext(env);
    }

}
