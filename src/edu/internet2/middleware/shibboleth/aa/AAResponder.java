package edu.internet2.middleware.shibboleth.aa;

//import aa.*;
import java.io.*;
import java.util.*;
import java.lang.reflect.*;
import javax.servlet.*;
import javax.servlet.http.*;
import javax.naming.*;
import javax.naming.directory.*;
import edu.internet2.middleware.shibboleth.*;
import edu.internet2.middleware.eduPerson.*;
import org.w3c.dom.*;
import org.opensaml.*;

public class AAResponder{

    //HandleRepositoryFactory hrf;
    ArpFactory arpFactory;
    Arp adminArp;
    DirContext ctx;
    String domain;

    public AAResponder(/*HandleRepositoryFactory*/String hrf, ArpFactory arpFactory, DirContext ctx, String domain)
	throws AAException{

	//this.hrf = hrf;
	this.arpFactory = arpFactory;
	adminArp = arpFactory.getInstance("admin", true);
	if(adminArp.isNew())
	    throw new AAException("Admin Arp not found in "+arpFactory);
	this.ctx = ctx;
	this.domain = domain;
    }


    public SAMLAttribute[] getReleaseAttributes(String uidSyntax, String handle, String sharName, String url)
	throws AAException/*,HandleException*/ {

	DirContext userCtx = null;
	//HandleEntry he = hrf.getHandleEntry(handle);
	// temp for testing
	String userName = null;
	if(handle.equalsIgnoreCase("foo"))
	   userName = "dousti"; //he.getUsername();
	    
	if(userName == null)
	    throw new AAException("user name is null");

	try{
	    if(uidSyntax == null)
		uidSyntax = "";
	    userCtx = (DirContext)ctx.lookup(uidSyntax+"="+userName);
	}catch(NamingException e){
	    throw new AAException("Cannot lookup context for "+userName+" :"+e);
	}



	Set s = getCombinedReleaseSet(adminArp, sharName, url, userName);
	// go throu the set and find values for each attribute
	try{
	    Vector sAttrs = new Vector();
	    Iterator it = s.iterator();
	    while(it.hasNext()){
		ArpAttribute aAttr = (ArpAttribute)it.next();
		Attribute dAttr = aAttr.getDirAttribute(userCtx, true);
		if(dAttr != null){
		    SAMLAttribute sAttr = jndi2saml(dAttr);
		    sAttrs.add(sAttr);
		}
	    }
	    SAMLAttribute[] sa = new SAMLAttribute[sAttrs.size()];
	    return (SAMLAttribute[])sAttrs.toArray(sa);
	}catch(NamingException e){
	    throw new AAException("Bad Contexted for getting Attribute Values: "+e);
	}
    }


    private Set getCombinedReleaseSet(Arp admin, String sharName, String url, String userName)
	throws AAException {
	
	Set adminSet;
	Set userSet;


	Arp userArp = arpFactory.getInstance(userName, false);	
	if(userArp.isNew()){
	    // no user ARP just use the admin
	    // only go throu and drop the exclude ones
	    adminSet = getReleaseSet(adminArp, sharName, url, adminArp);
	    Iterator it = adminSet.iterator();
	    while(it.hasNext()){
		ArpAttribute attr = (ArpAttribute)it.next();
		if(attr.mustExclude())
		    adminSet.remove(attr);
	    }
	    return adminSet;
	}

	adminSet = getReleaseSet(adminArp, sharName, url, adminArp);
	userSet = getReleaseSet(userArp, sharName, url, adminArp);
	// combine the two
	Iterator it = adminSet.iterator();
	while(it.hasNext()){
	    ArpAttribute aAttr = (ArpAttribute)it.next();
	    if(aAttr.mustExclude()){
		userSet.remove(aAttr);  // ok if not there
		adminSet.remove(aAttr);
	    }
	    if(userSet.contains(aAttr)){
		// in both. Combine filters
		ArpFilter f = combineFilters(aAttr, getAttr(userSet, aAttr));
		System.out.println("debug: Combine filters: "+
				   aAttr.getFilter()+ " AND "+
				   getAttr(userSet, aAttr).getFilter()+
				   " = " + f);
		if(f != null)
		    aAttr.setFilter(f, true); // force it
		userSet.remove(aAttr);
	    }
	}
	adminSet.addAll(userSet);
	return adminSet;

    }		    
		    

    private Set getReleaseSet(Arp arp, String sharName, String url, Arp admin)
	throws AAException{

	boolean usingDefault = false;

	System.out.println("debug: using ARP: "+arp);

	ArpShar shar = arp.getShar(sharName);
	if(shar == null){
	    shar = admin.getDefaultShar();
	    usingDefault = true;
	}
	if(shar == null)
	    throw new AAException("No default SHAR.");

	System.out.println("debug:\t using shar: "+shar+(usingDefault?"(default)":""));
	System.out.println("debug:\t using url: "+url);

	if(url == null || url.length() == 0)
	    throw new AAException("Given url to AA is null or blank");

	ArpResource resource = shar.bestFit(url);
	System.out.println("debug:\t\t best fit is: "+resource);
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
	    System.out.println("debug:\t\t\t attribute: "+attrs[i]+" FILTER: "+attrs[i].getFilter());
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
    
    private SAMLAttribute jndi2saml(Attribute jAttr)
	throws NamingException, AAException{

	if(jAttr == null)
	    return null;
	    
	String id = jAttr.getID();
	Vector vals = new Vector();

	NamingEnumeration ne = jAttr.getAll();
	while(ne.hasMore())
	    vals.add(ne.next());


	String[] scopes = { this.domain };
	Object[] args = new Object[2];
	args[0] = scopes;
	args[1] = vals.toArray();

	try{
	    Class attrClass = Class.forName(id);
	    Constructor[] cons = attrClass.getConstructors();
	    System.out.println("Got constructors for "+attrClass);
	    System.out.println("number of constructors "+cons.length);
	    System.out.println("first constructor is "+cons[0]);
	    return (SAMLAttribute)cons[0].newInstance(args);
	}catch(Exception e){
	    throw new AAException("Failed to read the class for attribute "+id+" :"+e);
	}

    }
}
