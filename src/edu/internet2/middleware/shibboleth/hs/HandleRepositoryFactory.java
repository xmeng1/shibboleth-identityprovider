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

import java.lang.reflect.Constructor;
import java.util.Properties;

import org.apache.log4j.Logger;

/**
 * Factory for generating instances of <code>HandleRepository</code>.  Configuration
 * is delegated to the Handle Repository.  Runtime options are passed to concrete constructors
 * via a <code>Properties</code> object.
 *
 * @author Walter Hoehn (wassa@columbia.edu)
 */

public class HandleRepositoryFactory {

	private static Logger log = Logger.getLogger(HandleRepositoryFactory.class.getName());

    public static HandleRepository getInstance(String className, Properties props) throws HandleRepositoryException {
        if (className == null) {
            throw new HandleRepositoryException("No Handle Repository implementation specified.");
        }
        try {
            Class implementorClass = Class.forName(className);
            Class[] params = new Class[] { Properties.class };
            Constructor implementorConstructor = implementorClass.getConstructor(params);
            Object[] args = new Object[] { props };
            log.debug("Initializing Handle Repository of type (" + implementorClass.getName() + ").");
            return (HandleRepository) implementorConstructor.newInstance(args);

        } catch (NoSuchMethodException nsme) {
            log.error(
                "Failed to instantiate an Handle Repository: HandleRepository "
                    + "implementation must contain a constructor that accepts a Properties bundle for "
                    + "configuration data.");
            throw new HandleRepositoryException("Failed to instantiate a Handle Repository.");
        } catch (Exception e) {

            log.error("Failed to instantiate a Handle Repository: " + e + ":" + e.getCause());
            throw new HandleRepositoryException("Failed to instantiate a Handle Repository: " + e);

        }
    }

	public static HandleRepository getInstance(Properties props) throws HandleRepositoryException {

		if (props.getProperty("edu.internet2.middleware.shibboleth.hs.HandleRepository.implementation") == null) {
			throw new HandleRepositoryException("No Handle Repository implementation specified.");
		}
		return getInstance(
            props.getProperty("edu.internet2.middleware.shibboleth.hs.HandleRepository.implementation"),
            props
            );
	}
}
