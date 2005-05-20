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

package edu.internet2.middleware.shibboleth.metadata;

import java.util.Iterator;

import org.w3c.dom.Element;

/**
 * <p>
 * Corresponds to SAML Metadata Schema "AffiliationDescriptorType".
 * 
 * @author Scott Cantor
 */
public interface AffiliationDescriptor {

	public EntityDescriptor getEntityDescriptor(); // parent EntityDescriptor

	public String getOwnerID();

	public boolean isValid();

	public Iterator /* <String> */getMembers();

	public boolean isMember(String id);

	public Iterator /* <KeyDescriptor> */getKeyDescriptors(); // direct or indirect key references

	public Element getElement(); // punch through to XML content if permitted
}
