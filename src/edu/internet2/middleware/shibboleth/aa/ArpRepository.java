package edu.internet2.middleware.shibboleth.aa;

/**
 *  Attribute Authority & Release Policy
 *  Factory for generating ARP managers/factories.
 *
 * @author     Parviz Dousti (dousti@cmu.edu)
 * @created    June, 2002
 */

public class ArpRepository{


    /**
     * This is a method to allow implementation of different 
     * repositories for ARPs. e.g. File system, SQL database, or LDAP
     * It returns an implementation based on the given method.  
     * It passes the given data string to the implementation.  Data string is 
     * opeque and only meaningful to the specific implementation.
     * e.g. it might be a directory path to file system implementation.
     */

    public static ArpFactory getInstance(String method, String pathData)
	throws AAException{
	if(method.equalsIgnoreCase("file"))
	    return new ArpFileFactory(pathData);
	else
	    throw new AAException("Unknown repository or not implemented yet:" +method);

    }
}

