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
 * Defines a plugin for the AA Attribute Resolver. Such plugins can be realized at runtime by the resolver.
 * 
 * @author Walter Hoehn
 * 
 */
public interface ResolutionPlugIn {

	/**
	 * Returns the name of the plugin.
	 * 
	 * @return String a plugin name
	 */
	public String getId();

	/**
	 * Returns the time in seconds to cache the results of the plugin's resolution.
	 * 
	 * @return long time in seconds
	 */
	public long getTTL();

	/**
	 * Returns whether to trap and log resolution errors and return nothing, or propagate errors up as exceptions.
	 * 
	 * @return boolean whether to propagate errors
	 */
	public boolean getPropagateErrors();

	/**
	 * Returns an array containing the names of the attribute definitions that this definition depends upon for
	 * resolution.
	 * 
	 * @return String[] an array of Ids
	 */
	public String[] getAttributeDefinitionDependencyIds();

	/**
	 * Returns an array containining the names of the connectors that this definition depends upon for resolution.
	 * 
	 * @return String[] an array of Ids
	 */
	public String[] getDataConnectorDependencyIds();
}
