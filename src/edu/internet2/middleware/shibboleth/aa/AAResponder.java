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

/**
 *  Attribute Authority & Release Policy
 *  Main logic that decides what to release 
 *
 * @author     Parviz Dousti (dousti@cmu.edu)
 * @created    June, 2002
 */


import java.io.*;
import java.util.*;
import java.lang.reflect.*;
import javax.servlet.*;
import javax.servlet.http.*;
import javax.naming.*;
import javax.naming.directory.*;
import edu.internet2.middleware.shibboleth.*;
import edu.internet2.middleware.shibboleth.hs.*;
import edu.internet2.middleware.eduPerson.*;
import org.w3c.dom.*;
import org.opensaml.*;
import org.apache.log4j.Logger;

public class AAResponder{

    ArpRepository arpFactory;
    Arp adminArp;
    DirContext ctx;
    String domain;
    private static Logger log = Logger.getLogger(AAResponder.class.getName());    

    public AAResponder(ArpRepository arpFactory, DirContext ctx, String domain)
	throws AAException{

	this.arpFactory = arpFactory;
	try {
		adminArp = arpFactory.lookupArp("admin", true);
	} catch (ArpRepositoryException e) {
		log.error("Error while searching Arp Repository (" + arpFactory + ") : " + e.getMessage());
	    throw new AAException("Unable to load admin ARP.");
	}
	if(adminArp ==  null) {
		log.error("Admin ARP not found in Arp Repository (" + arpFactory + ").");
	    throw new AAException("Unable to load admin ARP.");
	}
	this.ctx = ctx;
	this.domain = domain;
    }


	public SAMLAttribute[] getReleaseAttributes(
		String userName,
		String searchFilter,
		String handle,
		String sharName,
		String url)
		throws AAException {

		DirContext userCtx = null;

		try {
			if (searchFilter == null)
				searchFilter = "";
			int indx = searchFilter.indexOf("%s");
			if (indx < 0) {
				try {
					userCtx = (DirContext) ctx.lookup(searchFilter + userName);
				} catch (NameNotFoundException nnfe) {
					log.error(
						"Could not locate a user ("
							+ userName
							+ ") as a result of searching with ("
							+ searchFilter
							+ ").");
					throw new AAException("No data available for this principal.");
				}
			} else {
				/* This is a search filter. Search after replacing %s with uid*/
				StringBuffer tmp = new StringBuffer(searchFilter);
				tmp.delete(indx, indx + 2);
				tmp.insert(indx, userName);
				searchFilter = tmp.toString();
				SearchControls ctls = new SearchControls();
				ctls.setReturningObjFlag(true);
				NamingEnumeration en = ctx.search("", searchFilter, ctls);
				if (!en.hasMore()) {
					log.error(
						"Could not locate a user ("
							+ userName
							+ ") as a result of searching with ("
							+ searchFilter
							+ ").");
					throw new AAException("No data available for this principal.");
				}
				userCtx = (DirContext) ((SearchResult) en.next()).getObject();
				if (en.hasMore()) {
					log.error(
						"Located multiple ("
							+ userName
							+ ") users as a result of searching with ("
							+ searchFilter
							+ ").");
					throw new AAException("Cannot disambiguate data for this principal.");
				}
			}
		} catch (NamingException e) {
			log.error(
				"An error occurred while retieving data for principal (" + userName + ") :" + e.getMessage());
			throw new AAException("Error retrieving data for principal (" + userName + ")");
		}

		Set s = getCombinedReleaseSet(adminArp, sharName, url, userName);
		// go throu the set and find values for each attribute
		try {
			Vector sAttrs = new Vector();
			Iterator it = s.iterator();
			while (it.hasNext()) {
				ArpAttribute aAttr = (ArpAttribute) it.next();
				Attribute dAttr = aAttr.getDirAttribute(userCtx, true);
				if (dAttr != null) {
					SAMLAttribute sAttr = jndi2saml(dAttr);
					if (sAttr != null) {
						sAttrs.add(sAttr);
					}
				}
			}
			SAMLAttribute[] sa = new SAMLAttribute[sAttrs.size()];
			return (SAMLAttribute[]) sAttrs.toArray(sa);
		} catch (NamingException e) {
			log.error(
				"An error occurred while retieving data for principal (" + userName + ") :" + e.getMessage());
			throw new AAException("Error retrieving data for principal (" + userName + ")");
		}
	}


	private Set getCombinedReleaseSet(Arp admin, String sharName, String url, String userName)
		throws AAException {

		try {
			Set adminSet;
			Set userSet;
			Arp userArp;

			userArp = arpFactory.lookupArp(userName, false);

			if (userArp == null) {
				// no user ARP just use the admin
				// only go throu and drop the exclude ones
				adminSet = getReleaseSet(adminArp, sharName, url, adminArp);
				Iterator it = adminSet.iterator();
				while (it.hasNext()) {
					ArpAttribute attr = (ArpAttribute) it.next();
					if (attr.mustExclude())
						adminSet.remove(attr);
				}
				return adminSet;
			}

			adminSet = getReleaseSet(adminArp, sharName, url, adminArp);
			userSet = getReleaseSet(userArp, sharName, url, adminArp);
			// combine the two
			Iterator it = adminSet.iterator();
			while (it.hasNext()) {
				ArpAttribute aAttr = (ArpAttribute) it.next();
				if (aAttr.mustExclude()) {
					userSet.remove(aAttr); // ok if not there
					adminSet.remove(aAttr);
				}
				if (userSet.contains(aAttr)) {
					// in both. Combine filters
					ArpFilter f = combineFilters(aAttr, getAttr(userSet, aAttr));
					log.info(
						"Combining filters: "
							+ aAttr.getFilter()
							+ " AND "
							+ getAttr(userSet, aAttr).getFilter()
							+ " = "
							+ f);
					if (f != null)
						aAttr.setFilter(f, true); // force it
					userSet.remove(aAttr);
				}
			}
			adminSet.addAll(userSet);
			return adminSet;

		} catch (ArpRepositoryException e) {
			log.error("Error while searching Arp Repository (" + arpFactory + ") : " + e.getMessage());
			throw new AAException("Unable to load user ARP.");
		}

	}		    
		    

    private Set getReleaseSet(Arp arp, String sharName, String url, Arp admin)
	throws AAException{

	boolean usingDefault = false;

	log.info("using ARP: "+arp);

	ArpShar shar = arp.getShar(sharName);
	if(shar == null){
	    shar = admin.getDefaultShar();
	    usingDefault = true;
	}
	if(shar == null)
	    throw new AAException("No default SHAR.");

	log.debug("\t using shar: "+shar+(usingDefault?"(default)":""));
	log.debug("\t using url: "+url);

	if(url == null || url.length() == 0)
	    throw new AAException("Given url to AA is null or blank");

	ArpResource resource = shar.bestFit(url);
	log.debug("\t\t best fit is: "+resource);
	if(resource == null){
	    if(usingDefault)
		return new HashSet(); // empty set

	    shar = admin.getDefaultShar();
	    if(shar == null)
		throw new AAException("No default SHAR.");

	    resource = shar.bestFit(url);
	    if(resource == null)
		return new HashSet(); // empty set
	}
	Set s = new HashSet();
	ArpAttribute[] attrs = resource.getAttributes();
	for(int i=0; i<attrs.length; i++){
	    log.info("\t\t\t attribute: "+attrs[i]+" FILTER: "+attrs[i].getFilter());
	    s.add(attrs[i]);
	}
	return s;
    }

    private ArpFilter combineFilters(ArpAttribute attr1, ArpAttribute attr2){

	ArpFilter filt1 = attr1.getFilter();
	ArpFilter filt2 = attr2.getFilter();
	
	if(filt1 == null)
	    return filt2;

	if(filt2 == null)
	    return filt1;

	ArpFilterValue[]  fv1Array = filt1.getFilterValues();
	
	for(int i=0; i<fv1Array.length; i++){
	    ArpFilterValue afv = fv1Array[i];

	    if(afv.mustInclude()){  // cannot be filtered out
		filt2.removeFilterValue(afv); // ok if not there
	    }else{
		filt2.addAFilterValue(afv);
	    }
	}

	return filt2;
    
    }
    

    private ArpAttribute getAttr(Set s, ArpAttribute a){
	Iterator it = s.iterator();
	while(it.hasNext()){
	    ArpAttribute attr = (ArpAttribute)it.next();
	    if(attr.equals(a))
		return attr;
	}
	return null;
    }
    
	private SAMLAttribute jndi2saml(Attribute jAttr) throws NamingException, AAException {

		if (jAttr == null) {
			return null;
		}

		log.debug("Converting Attribute (" + jAttr.getID() + ") to SAML.");
		Vector vals = new Vector();

		NamingEnumeration ne = jAttr.getAll();

		while (ne.hasMore()) {
			vals.add(ne.next());
		}

		try {
			Class attrClass = Class.forName("edu.internet2.middleware.shibboleth.aaLocal.attributes." + jAttr.getID());
			log.debug("Loaded the class for " + attrClass);
			ShibAttribute sa = (ShibAttribute) attrClass.newInstance();
			return sa.toSamlAttribute(this.domain, vals.toArray());
			
		} catch (SAMLException e) {
			log.error("Error converting attribute to SAML (" + jAttr.getID() + ") :" + e.getMessage());
			return null;
		} catch (Exception e) {
			log.error("Failed to load the class for attribute (" + jAttr.getID() + ") :" + e);
			return null;
		}

	}
}
