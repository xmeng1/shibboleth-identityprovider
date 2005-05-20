/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.aa.attrresolv.provider;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * <code>ValueHandler</code> implementation for String objects with a domain scope. Includes logic to add a default
 * scope to values that don't already include a scope.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */
public class ScopedStringValueHandler implements ValueHandler {

	private static Logger log = Logger.getLogger(ScopedStringValueHandler.class.getName());
	public String smartScope;

	public ScopedStringValueHandler(String smartScope) {

		this.smartScope = smartScope;
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.provider.ValueHandler#toDOM(org.w3c.dom.Element,
	 *      java.lang.Object, org.w3c.dom.Document)
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

	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	public boolean equals(Object object) {

		if (!(object instanceof ScopedStringValueHandler)) { return false; }
		return smartScope.equals(((ScopedStringValueHandler) object).smartScope);
	}

}
