package edu.internet2.middleware.shibboleth.hs

import edu.internet2.middleware.shibboleth.*;
import edu.internet2.middleware.shibboleth.common.*;
import org.opensaml.*;
import java.util.*;
import HandleException;
import org.doomdark.uuid.*;

/**
 *  Object all user information is kept in
 *
 * @author    Barbara Jensen
 */
public class HandleEntry {
    /** opaque handle, based off MAC address and time */
    protected String handle;
    /** username, passed in from RemoteUser */
    protected String username;
    /** authentication type, passed from AuthType */
    protected String authType;
    /** instant of handle creation */
    protected long authInstant;
    /** instant of handle expiration, based on ticket length */
    protected long expInstant;
    
    /**
     *  HandleEntry object, created from HandleService
     *
     */
    public HandleEntry ( String username, String authType, 
			 long ticketLength ) 
	throws HandleException
    {
	if (username == null || username.length() == 0) 
	    throw new HandleException(HandleException.ERR, "HandleEntry() requires username");
	if (authType == null || authType.length() == 0)
	    throw new HandleException(HandleException.ERR, "HandleEntry() requires authType");

	handle = UUIDGenerator.getInstance().generateRandomBasedUUID().toString();
	this.username = username;
	this.authType = authType;
	this.authInstant= System.currentTimeMillis();
	this.expInstant = authInstant+ticketLength;
    }

    /** 
     *  HandleEntry object, created from all parts 
     * 
     */
    public HandleEntry ( String handle, String username, String authType,
			 long authInstant, long expInstant ) 
	throws HandleException 
    {
	if (handle == null || handle.length() == 0) 
	    throw new HandleException(HandleException.ERR, "HandleEntry() requires handle");
	if (username == null || username.length() == 0) 
	    throw new HandleException(HandleException.ERR, "HandleEntry() requires username");
	if (authType == null || authType.length() == 0)
	    throw new HandleException(HandleException.ERR, "HandleEntry() requires authType");
	
	this.handle = handle;
	this.username = username;
	this.authType = authType;
	this.authInstant = authInstant;
	this.expInstant = expInstant;
    }

    /** 
     *  Gets the HandleEntry's handle string 
     * 
     */
    public String getHandle () {
	return handle;
    }
    
    /**
     *  Gets the HandleEntry's username 
     * 
     */
    public String getUsername () {
	return username;
    }

    /**
     *  Gets the HandleEntry's authentication type
     * 
     */
    public String getAuthType () {
	return authType;
    } 

    /**
     *  Gets the HandleEntry's creation/authentication date
     * 
     */
    public long getAuthInstant () {
	return authInstant;
    }

    /**
     *  Gets the HandleEntry's expiration date
     * 
     */
    public long getExpInstant () {
	return expInstant;
    }

}

