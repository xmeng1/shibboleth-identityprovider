/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.] Licensed under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in
 * writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.aa;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.xml.namespace.QName;

import org.apache.log4j.Logger;
import org.opensaml.SAMLAttribute;
import org.opensaml.SAMLException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.aa.arp.ArpAttribute;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolverAttribute;
import edu.internet2.middleware.shibboleth.aa.attrresolv.provider.ValueHandler;
import edu.internet2.middleware.shibboleth.aa.attrresolv.provider.ValueHandlerException;

/**
 * An attribute for which the Shibboleth Attribute Authority has been asked to provide an assertion.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */
public class AAAttribute extends SAMLAttribute implements ResolverAttribute, ArpAttribute {

	private static Logger log = Logger.getLogger(AAAttribute.class.getName());
	private boolean resolved = false;

	/** Default lifetime, in seconds * */
	private static long defaultLifetime = 1800; // 30 minutes
	private ValueHandler valueHandler = new StringValueHandler();

	/**
	 * Constructs a skeleton attribute with no values.
	 * 
	 * @param name
	 *            the name of the attribute
	 * @param legacyCompat
	 *            boolean indicator of whether or not the legacy namespace hack should be used (this is required for SPs
	 *            running old versions of xerces)
	 * @throws SAMLException
	 */
	public AAAttribute(String name, boolean legacyCompat) throws SAMLException {

		super(name, null, legacyCompat ? new QName("urn:mace:shibboleth:1.0", "AttributeValueType") : null,
				defaultLifetime, null);
	}

	/**
	 * Constructs a skeleton attribute with no values.
	 * 
	 * @param name
	 *            the name of the attribute
	 * @throws SAMLException
	 *             if the attribute could not be created
	 */
	public AAAttribute(String name) throws SAMLException {

		super(name, null, null, defaultLifetime, null);
	}

	public AAAttribute(String name, Object[] values) throws SAMLException {

		this(name);
		setValues(values);
	}

	public AAAttribute(String name, Object[] values, ValueHandler handler) throws SAMLException {

		this(name);
		setValues(values);
		registerValueHandler(handler);
	}

	public boolean hasValues() {

		if (values.isEmpty()) { return false; }
		return true;
	}

	public Iterator getValues() {

		return valueHandler.getValues(values);
	}

	public void setValues(Object[] values) {

		if (!this.values.isEmpty()) {
			this.values.clear();
		}
		List newList = Arrays.asList(values);
		if (newList.contains(null)) {
			newList.remove(null);
		}
		this.values.addAll(newList);
	}

	/**
	 * @see java.lang.Object#hashCode()
	 */
	public int hashCode() {

		int code = 0;
		if (values != null) {
			Iterator iterator = values.iterator();
			while (iterator.hasNext()) {
				code += iterator.next().hashCode();
			}
		}
		return name.hashCode() + code;
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.ArpAttribute#resolved()
	 */
	public boolean resolved() {

		return resolved;
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.ArpAttribute#setResolved()
	 */
	public void setResolved() {

		resolved = true;
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.ArpAttribute#resolveFromCached(edu.internet2.middleware.shibboleth.aa.attrresolv.ArpAttribute)
	 */
	public void resolveFromCached(ResolverAttribute attribute) {

		if (this == attribute) { return; }

		resolved = true;
		setLifetime(attribute.getLifetime());

		if (!this.values.isEmpty()) {
			this.values.clear();
		}
		for (Iterator iterator = attribute.getValues(); iterator.hasNext();) {
			values.add(iterator.next());
		}

		registerValueHandler(attribute.getRegisteredValueHandler());
	}

	public void setLifetime(long lifetime) {

		this.lifetime = lifetime;

	}

	public void addValue(Object value) {

		if (value != null) {
			values.add(value);
		}
	}

	/*
	 * @see org.opensaml.SAMLAttribute#valueToDOM(int, org.w3c.dom.Element)
	 */
	protected void valueToDOM(int index, Element e) throws SAMLException {

		try {
			valueHandler.toDOM(e, values.get(index), e.getOwnerDocument());

		} catch (ValueHandlerException ex) {
			log.error("Value Handler unable to convert value to DOM Node: " + ex);
		}
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.ArpAttribute#registerValueHandler(edu.internet2.middleware.shibboleth.aa.attrresolv.provider.ValueHandler)
	 */
	public void registerValueHandler(ValueHandler handler) {

		valueHandler = handler;
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.ArpAttribute#getRegisteredValueHandler()
	 */
	public ValueHandler getRegisteredValueHandler() {

		return valueHandler;
	}

	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	public boolean equals(Object object) {

		if (!(object instanceof AAAttribute)) { return false; }
		if (lifetime != ((AAAttribute) object).lifetime) { return false; }
		if (!name.equals(((AAAttribute) object).name)) { return false; }
		if (!valueHandler.equals(((AAAttribute) object).valueHandler)) { return false; }

		ArrayList localValues = new ArrayList();
		for (Iterator iterator = getValues(); iterator.hasNext();) {
			localValues.add(iterator.next());
		}

		ArrayList objectValues = new ArrayList();
		for (Iterator iterator = ((AAAttribute) object).getValues(); iterator.hasNext();) {
			objectValues.add(iterator.next());
		}

		return localValues.equals(objectValues);
	}

}

/**
 * Default <code>ValueHandler</code> implementation. Expects all values to be String objects.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */

class StringValueHandler implements ValueHandler {

	public void toDOM(Element valueElement, Object value, Document document) {

		valueElement.appendChild(document.createTextNode(value.toString()));
	}

	public Iterator getValues(Collection internalValues) {

		return internalValues.iterator();
	}

	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	public boolean equals(Object object) {

		if (object instanceof StringValueHandler) { return true; }
		return false;
	}

}
