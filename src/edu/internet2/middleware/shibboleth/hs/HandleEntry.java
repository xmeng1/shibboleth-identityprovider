/* 
 * The Shibboleth License, Version 1. 
 * Copyright (c) 2002 
 * University Corporation for Advanced Internet Development, Inc. 
 * All rights reserved
 * 
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this 
 * list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, 
 * this list of conditions and the following disclaimer in the documentation 
 * and/or other materials provided with the distribution, if any, must include 
 * the following acknowledgment: "This product includes software developed by 
 * the University Corporation for Advanced Internet Development 
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement 
 * may appear in the software itself, if and wherever such third-party 
 * acknowledgments normally appear.
 * 
 * Neither the name of Shibboleth nor the names of its contributors, nor 
 * Internet2, nor the University Corporation for Advanced Internet Development, 
 * Inc., nor UCAID may be used to endorse or promote products derived from this 
 * software without specific prior written permission. For written permission, 
 * please contact shibboleth@shibboleth.org
 * 
 * Products derived from this software may not be called Shibboleth, Internet2, 
 * UCAID, or the University Corporation for Advanced Internet Development, nor 
 * may Shibboleth appear in their name, without prior written permission of the 
 * University Corporation for Advanced Internet Development.
 * 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK 
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE. 
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY 
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT, 
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.hs;

import edu.internet2.middleware.shibboleth.*;
import edu.internet2.middleware.shibboleth.common.*;
import org.opensaml.*;
import java.util.*;
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

