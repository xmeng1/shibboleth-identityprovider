package edu.internet2.middleware.shibboleth.aaLocal;


/**
 *  Attribute Authority & Release Policy
 *  Very simple implementation of directory layer.
 *
 * @author     Parviz Dousti (dousti@cmu.edu)
 * @created    June, 2002
 */


import java.util.Hashtable;
import javax.naming.*;
import javax.naming.spi.*;


public class EchoCtxFactory implements InitialContextFactory{

    public Context getInitialContext(Hashtable env)
	throws NamingException{
	return new EchoDirContext(env);
    }

}
