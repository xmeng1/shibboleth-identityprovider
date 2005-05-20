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

package edu.internet2.middleware.shibboleth.aa;

import java.util.HashMap;
import java.util.Iterator;

import org.opensaml.SAMLAttribute;

import edu.internet2.middleware.shibboleth.aa.arp.ArpAttribute;
import edu.internet2.middleware.shibboleth.aa.arp.ArpAttributeSet;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolverAttribute;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolverAttributeSet;

/**
 * A set of attributes for which the Shibboleth Attribute Authority has been asked to provide assertions.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */
public class AAAttributeSet implements ResolverAttributeSet, ArpAttributeSet {

	private HashMap attributes = new HashMap();

	public AAAttributeSet() {

	}

	public AAAttributeSet(AAAttribute attribute) {

		attributes.put(attribute.getName(), attribute);
	}

	public AAAttributeSet(AAAttribute[] attributes) {

		for (int i = 0; i < attributes.length; i++) {
			this.attributes.put(attributes[i].getName(), attributes[i]);
		}
	}

	public void add(AAAttribute attribute) {

		attributes.put(attribute.getName(), attribute);
	}

	public ResolverAttribute getByName(String name) {

		return (ResolverAttribute) attributes.get(name);
	}

	public ShibAttributeIterator shibAttributeIterator() {

		return new ShibAttributeIterator(attributes.values().iterator());
	}

	public ResolverAttributeIterator resolverAttributeIterator() {

		return shibAttributeIterator();
	}

	public ArpAttributeIterator arpAttributeIterator() {

		return shibAttributeIterator();
	}

	public int size() {

		return attributes.size();
	}

	public SAMLAttribute[] getAttributes() {

		return (SAMLAttribute[]) attributes.values().toArray(new SAMLAttribute[0]);
	}

	public class ShibAttributeIterator implements ResolverAttributeIterator, ArpAttributeIterator {

		private Iterator genericIterator;

		private ShibAttributeIterator(Iterator iterator) {

			genericIterator = iterator;
		}

		public boolean hasNext() {

			return genericIterator.hasNext();
		}

		public ResolverAttribute nextResolverAttribute() {

			return nextShibAttribute();
		}

		public AAAttribute nextShibAttribute() {

			return (AAAttribute) genericIterator.next();
		}

		public void remove() {

			genericIterator.remove();
		}

		public ArpAttribute nextArpAttribute() {

			return (ArpAttribute) genericIterator.next();
		}

	}

	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	public boolean equals(Object object) {

		if (!(object instanceof AAAttributeSet)) { return false; }
		return attributes.equals(((AAAttributeSet) object).attributes);
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	public String toString() {

		StringBuffer buffer = new StringBuffer();
		buffer.append(attributes.size());
		for (Iterator iterator = attributes.values().iterator(); iterator.hasNext();) {
			AAAttribute attribute = (AAAttribute) iterator.next();
			buffer.append("(" + attribute.getName() + "):");
			for (Iterator valuesIterator = attribute.getValues(); valuesIterator.hasNext();) {
				buffer.append(" \"" + valuesIterator.next().toString() + "\"");
			}
			buffer.append(System.getProperty("line.separator"));
		}
		return buffer.toString();
	}

}
