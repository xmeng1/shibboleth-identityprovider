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

package edu.internet2.middleware.shibboleth.aa;

import java.util.HashMap;
import java.util.Iterator;

import org.opensaml.SAMLAttribute;

import edu.internet2.middleware.shibboleth.aa.arp.ArpAttribute;
import edu.internet2.middleware.shibboleth.aa.arp.ArpAttributeSet;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolverAttribute;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolverAttributeSet;

/**
 * A set of attributes for which the Shibboleth Attribute Authority has been asked
 * to provide assertions.
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
		return (SAMLAttribute[]) attributes.entrySet().toArray(new SAMLAttribute[0]);
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
		if (!(object instanceof AAAttributeSet)) {
			return false;
		}
		return attributes.equals(((AAAttributeSet) object).attributes);
	}

}
