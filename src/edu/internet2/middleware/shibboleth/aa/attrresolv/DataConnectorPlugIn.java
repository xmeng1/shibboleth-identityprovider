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

import java.security.Principal;

import javax.naming.directory.Attributes;

/**
 * Defines a Data Connector PlugIn for the AA Attribute Resolver. Such plugins represent connection points to external
 * data sources from which attribute data is gathered.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */

public interface DataConnectorPlugIn extends ResolutionPlugIn {

	/**
	 * Returns the name of a data connector to resolve if this one fails.
	 * 
	 * @return String an Id
	 */
	public String getFailoverDependencyId();

	/**
	 * Resolves the values of a data connector.
	 * 
	 * @param principal
	 *            The principal for which the connector should be resolved
	 * @param requester
	 *            The name of the entity making the resolution request *
	 * @param responder
	 *            The name of the entity responding to the resolution request
	 * @param depends
	 *            Resolution dependencies
	 * @throws ResolutionPlugInException
	 */
	public Attributes resolve(Principal principal, String requester, String responder, Dependencies depends)
			throws ResolutionPlugInException;

}
