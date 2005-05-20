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

package edu.internet2.middleware.shibboleth.aa.attrresolv;

import java.util.Iterator;

import edu.internet2.middleware.shibboleth.aa.attrresolv.provider.ValueHandler;

/**
 * Defines an attribute that can be resolved by the <code>AttributeResolver</code>.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */

public interface ResolverAttribute {

	/** Returns the Name of the attribute. */
	public String getName();

	/** Boolean indicator of whether the attribute has been resolved by the Attribute Resolver. */
	public boolean resolved();

	/** This method signals that the attribute has been resolved by the Attribute Resolver. */
	public void setResolved();

	/**
	 * Resolves the attribute based on a previous resolution.
	 * 
	 * @param attribute
	 *            the previously resolved attribute
	 */
	public void resolveFromCached(ResolverAttribute attribute);

	/** Sets the time, in seconds, for which this attribute is valid. */
	public void setLifetime(long lifetime);

	public void setNamespace(String namespace);

	/** Returns the time, in seconds, for which this attribute is valid. */
	public long getLifetime();

	public void addValue(Object value);

	public Iterator getValues();

	public boolean hasValues();

	public void registerValueHandler(ValueHandler handler);

	public ValueHandler getRegisteredValueHandler();
}