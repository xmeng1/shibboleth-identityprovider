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

package edu.internet2.middleware.shibboleth.aa.attrresolv.provider;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * <code>ValueHandler</code> implementation for String objects with a domain scope.  Includes logic to add
 * a default scope to values that don't already include a scope.
 *
 * @author Walter Hoehn (wassa@columbia.edu)
 */
class ScopedStringValueHandler implements ValueHandler {

	private static Logger log = Logger.getLogger(ScopedStringValueHandler.class.getName());
	public String smartScope;

	public ScopedStringValueHandler(String smartScope) {
		this.smartScope = smartScope;
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.provider.ValueHandler#toDOM(org.w3c.dom.Element, java.lang.Object, org.w3c.dom.Document)
	 */
	public void toDOM(Element valueElement, Object value, Document document) throws ValueHandlerException {

		if (value instanceof String) {
			String raw = (String) value;
			int divider = raw.indexOf("@");
			if (divider > 0) {
				log.debug("Using scope (" + raw.substring(divider + 1) + ") for value.");
				valueElement.appendChild(document.createTextNode(raw.substring(0, divider)));
				valueElement.setAttributeNS(null, "Scope", raw.substring(divider + 1));
			} else {
				log.debug("Adding defult scope of (" + smartScope + ") to value.");
				valueElement.appendChild(document.createTextNode(raw));
				valueElement.setAttributeNS(null, "Scope", smartScope);
			}
			return;
		}
		throw new ValueHandlerException("ScopedStringValueHandler called for non-String object.");
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.provider.ValueHandler#getValues(java.util.Collection)
	 */
	public Iterator getValues(Collection internalValues) {

		ArrayList values = new ArrayList();
		for (Iterator iterator = internalValues.iterator(); iterator.hasNext();) {
			Object value = iterator.next();
			if (value instanceof String) {
				String raw = (String) value;
				int divider = raw.indexOf("@");
				if (divider > 0) {
					values.add(raw);
				} else {
					values.add(raw + "@" + smartScope);
				}
				continue;
			}
			log.error("ScopedStringValueHandler called for non-String object.");
		}
		return values.iterator();
	}

}
