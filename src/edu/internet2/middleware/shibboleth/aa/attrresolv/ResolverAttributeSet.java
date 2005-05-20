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

/**
 * Defines a set of attributes that can be resolved by the <code>AttributeResolver</code>.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */
public interface ResolverAttributeSet {

	public ResolverAttributeIterator resolverAttributeIterator();

	public ResolverAttribute getByName(String name);

	public interface ResolverAttributeIterator {

		public boolean hasNext();

		public ResolverAttribute nextResolverAttribute();

		public void remove();
	}
}
