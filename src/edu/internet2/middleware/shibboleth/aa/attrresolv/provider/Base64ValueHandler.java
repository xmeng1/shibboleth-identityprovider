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

import java.util.Collection;
import java.util.Iterator;

import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * <code>ValueHandler</code> implementation for encoding byte array values in Base64..
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */
public class Base64ValueHandler implements ValueHandler {

	public void toDOM(Element valueElement, Object value, Document document) throws ValueHandlerException {

		if (!(value instanceof byte[])) { throw new ValueHandlerException(
				"Base64ValueHandler could not encode a value of type: " + value.getClass().getName()); }
		valueElement.appendChild(document.createTextNode(new String(Base64.encode((byte[]) value))));
	}

	public Iterator getValues(Collection internalValues) {

		return internalValues.iterator();
	}

	public boolean equals(Object object) {

		if (object instanceof Base64ValueHandler) { return true; }
		return false;
	}

}