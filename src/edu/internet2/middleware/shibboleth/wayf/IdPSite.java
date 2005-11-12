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

package edu.internet2.middleware.shibboleth.wayf;

import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.StringTokenizer;
import java.util.TreeSet;

import edu.internet2.middleware.shibboleth.metadata.EntitiesDescriptor;
import edu.internet2.middleware.shibboleth.metadata.EntityDescriptor;
import edu.internet2.middleware.shibboleth.metadata.Metadata;

import edu.internet2.middleware.shibboleth.metadata.Organization;

public class IdPSite implements Comparable {

	private final EntityDescriptor entity;
	
	public IdPSite(EntityDescriptor entity)
	{
		this.entity = entity;
	}
	
	public String getName()
	{
		return entity.getId();
	}
	
	public String getDisplayName()
	{
		Organization org = entity.getOrganization();
		
		if (org == null) {
			return entity.getId();
		}
		else {
			return org.getDisplayName();
		}
	}
	
	public boolean equals(Object obj)
	{
		return ((obj instanceof IdPSite) && (((IdPSite)obj).getName().equals(getName())));
	}

	/**
	 * Based on 1.2 Origin.isMatch.  There must have been a reason for it...
	 * [Kindas of] support for the search function in the wayf.  This return many false positives
	 * but given the aim is to provide input for a pull down list...
	 * 
	 * @param str      What to match
	 * @param config   Provides list of tokens to not lookup
	 * @return         Whether this item matches  
	 */
	
	public int compareTo(Object o) {
		
		if (equals(o)) return 0;
		
		int result = getDisplayName().toLowerCase().compareTo(((IdPSite) o).getDisplayName().toLowerCase());
		if (result == 0) {
			result = getDisplayName().compareTo(((IdPSite) o).getDisplayName());
		}
		return result;
	}

	static private boolean isMatch(EntityDescriptor entity, String str, HandlerConfig config) {
		
		Enumeration input = new StringTokenizer(str);
		while (input.hasMoreElements()) {
			String currentToken = (String) input.nextElement();

			if (config.isIgnoredForMatch(currentToken)) {				
				continue;
			}
			
			currentToken = currentToken.toLowerCase(); 

			if (entity.getId().indexOf(currentToken) > -1) {
				return true; 
			}
					
			Organization org = entity.getOrganization();
			
			if (org != null) {
				
				if (org.getName().toLowerCase().indexOf(currentToken) > -1) {
					return true; 
				}
				
				if (org.getDisplayName().toLowerCase().indexOf(currentToken) > -1) {
					return true; 
				}
				 
			}
		}
		return false;
	}
	
	static public Collection /*<IdPSite>*/ seachForMatchingOrigins(Metadata metadata,
													String searchString, 
													HandlerConfig config)
	{
		TreeSet /*<IdPSite>*/ result = new TreeSet /*<IdPSite>*/ ();
		Iterator /*<EntityDescriptor>*/ entities = Entities(metadata);
		
		while (entities.hasNext()) {
				
			EntityDescriptor entity = (EntityDescriptor) entities.next();
				
			if ((entity.isValid() &&
				 entity.getIDPSSODescriptor(edu.internet2.middleware.shibboleth.common.XML.SHIB_NS) != null) &&
				 isMatch(entity, searchString, config)) {		

				result.add(new IdPSite(entity));
			}
		} // check entities 
		return result;
	}
	
	static public Collection /*<IdPSite>*/ getIdPSites(Metadata metadata)
	{
		TreeSet /*<IdPSite>*/ result = new TreeSet /*<IdPSite>*/ ();
		Iterator /*<EntityDescriptor>*/ entities = Entities(metadata);
		
		while (entities.hasNext()) {
			EntityDescriptor entity = (EntityDescriptor) entities.next();
			
			if (entity.isValid() &&
			    entity.getIDPSSODescriptor(edu.internet2.middleware.shibboleth.common.XML.SHIB_NS) != null) {

				result.add(new IdPSite(entity));
				}
		} // iterate over all entities
		return result;
	}
	
	/**
	 * Lookup
	 */
	public String getAddressFor() {
		return entity.getIDPSSODescriptor(edu.internet2.middleware.shibboleth.common.XML.SHIB_NS).getSingleSignOnServiceManager().getDefaultEndpoint().getLocation();
	}
	/**
	 * entitiesIterator:
	 * 
	 * Given a metadata object return an iterator which will enumerate all the
	 * entities inside it.  There are two options for what is at the root of metadata
	 * (either a single entity or a single entities list) so we just create the right 
	 * sort of iterator
	 * 
	 * @param metadata:  What to traverse
	 * @return an iterator
	 */
	
	private static Iterator /*<EntityDescriptor>*/ Entities(Metadata metadata) {

		EntitiesDescriptor entities = metadata.getRootEntities();
		EntityDescriptor entity = metadata.getRootEntity();

		if (entities != null) {
			return new EntityIterator(entities);
		}
		
		return Collections.singleton(entity).iterator();
	}
	
	private static class EntityIterator implements Iterator /*<EntityDescriptor>*/ {
		
		private Iterator /*<EntitiesDescriptor>*/ entitiesIterator;
		private Iterator /*<EntityDescriptor>*/ entityIterator;
		
		/**
		* An invariant of this class is that the inner iterator (entityIterator) should always be valid.
		* This means that when the current one is at the end we step the outer iterator (entitiesIterator)
		* along and get the next innter iterator.
		* 
		* However because the returned inner iterator may already be empty we need to 
		* loop until we either get to the end of the outer iterator or the inner iterator has a value
		* to return.  Think of it as priming a pump.
		*
		* This method does the work.  It is called at the start (in the constructor) and also whenever
		* any innter iterator reaches the end.
		*/

		private void getNextNonEmptyIterator() {
			while (!entityIterator.hasNext() && entitiesIterator.hasNext()) {
				entityIterator = new EntityIterator((EntitiesDescriptor) entitiesIterator.next());
			}
		}
		
		private EntityIterator(EntitiesDescriptor entities)
		{
			entitiesIterator = entities.getEntitiesDescriptors();
			entityIterator = entities.getEntityDescriptors();
			
			if (entitiesIterator == null) {
				entitiesIterator = new NullIterator /*<EntitiesDescriptor>*/();
			}
			
			if (entityIterator == null) {
				entityIterator = new NullIterator /*<EntityDescriptor>*/();
			}
			
			// prime the pump to get entityIterator valid.
			getNextNonEmptyIterator();
		}
		
		
		public boolean hasNext() {
			return entityIterator.hasNext();
		}
	
		public Object /*EntityDescriptor*/ next() {
			Object /*EntityDescriptor*/ ret = entityIterator.next();

			//
			// make entityIterator valid
			///
			getNextNonEmptyIterator();
			return ret;
		}
	
		public void remove() {
			entityIterator.remove();
		}
		
		// 
		// Implementation note - should be removed in Java 5 and replaced by
		// the iterator from an empty collection.
		//
		private static class NullIterator /*<E>*/ implements Iterator/*<E>*/ {

			public boolean hasNext() {
				return false;
			}

			public /*E*/ Object next() {
				throw new NoSuchElementException();
			}

			public void remove() {
				throw new UnsupportedOperationException();
			}
		} //NullIterator	
	} // Class EntitiesIterator
}	

