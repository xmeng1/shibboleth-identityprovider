package edu.internet2.middleware.shibboleth.aa;

/**
 *  Attribute Authority & Release Policy
 *  Common interface for all ARP repositories.
 *
 * @author     Parviz Dousti (dousti@cmu.edu)
 * @created    June, 2002
 */


public interface ArpFactory{


    /**
     * Returns an Arp instance. It tries to retrieve the Arp from a repository
     * If not found then creates a new emplty Arp.  
     * Arp can be check by its isNew() to see how it was generated
     */

    public Arp getInstance(String arpName, boolean isDefault)
	throws AAException;

    
    /**
     * Writes the given ARP back to the repository.
     */

    public void write(Arp arp) throws AAException;

    /**
     * Rereads the ARP if the version on storage is newer
     * than the one in memory.
     */

    public Arp reread(Arp arp) throws AAException;

    /**
     * Permanently removes the given ARP from the repository
     */

    public void remove(Arp arp) throws AAException;

}

