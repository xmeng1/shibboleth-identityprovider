/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation
 * for Advanced Internet Development, Inc. All rights reserved
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
 * <http://www.ucaid.edu> Internet2 Project. Alternately, this acknowledegement
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
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.common;

import java.lang.reflect.Constructor;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;

/**
 * @author Walter Hoehn
 */
public class NameMapper {

	private static Logger log = Logger.getLogger(NameMapper.class.getName());
	private Map byFormat = new HashMap();
	private static Map registeredMappingTypes = Collections.synchronizedMap(new HashMap());

	static {
		try {
			registeredMappingTypes.put(
				"CryptoHandleGenerator",
				Class.forName("edu.internet2.middleware.shibboleth.common.CryptoHandleGenerator"));

			registeredMappingTypes.put(
				"MemoryHandleGenerator",
				Class.forName("edu.internet2.middleware.shibboleth.common.MemoryHandleGenerator"));

			registeredMappingTypes.put(
				"PassThruNameIdentifier",
				Class.forName("edu.internet2.middleware.shibboleth.common.PassThruNameIdentifier"));

		} catch (ClassNotFoundException e) {
			log.error("Unable to pre-register Name mapping implementation types.");
		}
	}

	public void addNameMapping(Element e) throws NameIdentifierMappingException {

		if (!e.getTagName().equals("NameMapping")) {
			throw new IllegalArgumentException();
		}

		String type = ((Element) e).getAttribute("type");
		String implementation = ((Element) e).getAttribute("class");
		if (type != null && (!type.equals("")) && implementation != null && (!implementation.equals(""))) {
			log.error("Name Mapping has both a \"type\" and a \"class\" attribute. Only \"type\" will take effect.");
		}

		if (type != null && (!type.equals(""))) {

			Class registeredImplementation = (Class) registeredMappingTypes.get(type);
			if (registeredImplementation == null) {
				log.error("Name Mapping refers to an unregistered implementation type.");
				throw new NameIdentifierMappingException("Invalid mapping implementation specified.");
			}

			log.debug(
				"Found type ("
					+ type
					+ ") registered with an implementation class of ("
					+ registeredImplementation.getName()
					+ ").");
			addNameMapping(loadNameIdentifierMapping(registeredImplementation, e));

		} else if (implementation != null && (!implementation.equals(""))) {

			try {
				Class implementorClass = Class.forName(implementation);
				addNameMapping(loadNameIdentifierMapping(implementorClass, e));

			} catch (ClassNotFoundException cnfe) {
				log.error("Name Mapping refers to an implementation class that cannot be loaded: " + cnfe);
				throw new NameIdentifierMappingException("Invalid mapping implementation specified.");
			}

		} else {
			log.error("Name Mapping requires either a \"type\" or a \"class\" attribute.");
			throw new NameIdentifierMappingException("No mapping implementation specified.");
		}

	}

	public void addNameMapping(NameIdentifierMapping mapping) {
		byFormat.put(mapping.getNameIdentifierFormat(), mapping);

		/* Will probably bump this into an HS specific base class
		if (mapping.getId() != null && (!mapping.getId().equals(""))) {
			byId.put(mapping.getId(), mapping);
		}
		*/
	}

	public NameIdentifierMapping getNameIdentifierMappingByFormat(String format) {
		return (NameIdentifierMapping) byFormat.get(format);
	}

	protected NameIdentifierMapping loadNameIdentifierMapping(Class implementation, Element config)
		throws NameIdentifierMappingException {

		try {
			Class[] params = new Class[] { Element.class };
			Constructor implementorConstructor = implementation.getConstructor(params);
			Object[] args = new Object[] { config };
			log.debug("Initializing Name Identifier Mapping of type (" + implementation.getName() + ").");
			return (NameIdentifierMapping) implementorConstructor.newInstance(args);

		} catch (NoSuchMethodException nsme) {
			log.error(
				"Failed to instantiate a Name Identifier Mapping: NameIdentifierMapping "
					+ "implementation must contain a constructor that accepts an Element object for "
					+ "configuration data.");
			throw new NameIdentifierMappingException("Failed to instantiate a Name Identifier Mapping.");

		} catch (Exception e) {
			log.error("Failed to instantiate a Name Identifier Mapping: " + e + ":" + e.getCause());
			throw new NameIdentifierMappingException("Failed to instantiate a Name Identifier Mapping: " + e);

		}

	}

}
