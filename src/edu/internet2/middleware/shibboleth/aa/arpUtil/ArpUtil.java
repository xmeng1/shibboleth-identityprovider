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

package edu.internet2.middleware.shibboleth.aa.arpUtil;

/**
 *  Attribute Authority & Release Policy
 *  A utility for managing ARPs
 *
 * @author     Parviz Dousti (dousti@cmu.edu)
 * @created    June, 2002
 */

import java.security.Principal;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Properties;

import javax.naming.Context;
import javax.naming.directory.Attribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

import edu.internet2.middleware.shibboleth.aa.AAAttributes;
import edu.internet2.middleware.shibboleth.aa.AAException;
import edu.internet2.middleware.shibboleth.aa.AAPermissionException;
import edu.internet2.middleware.shibboleth.aa.AA_Identity;
import edu.internet2.middleware.shibboleth.aa.Arp;
import edu.internet2.middleware.shibboleth.aa.ArpAttribute;
import edu.internet2.middleware.shibboleth.aa.ArpFilter;
import edu.internet2.middleware.shibboleth.aa.ArpFilterValue;
import edu.internet2.middleware.shibboleth.aa.ArpRepository;
import edu.internet2.middleware.shibboleth.aa.ArpRepositoryFactory;
import edu.internet2.middleware.shibboleth.aa.ArpResource;
import edu.internet2.middleware.shibboleth.aa.ArpShar;

class ArpUtil{

    private static Logger log = Logger.getLogger(ArpUtil.class.getName());
    static Principal user;
    static ArpRepository arpFactory;
    static String listUsage = "\tArpUtil list <arp name> [-acls] [-dir <ldap url> <user id>]";
    static String addUsage = "\tArpUtil add <arp name> [-admin] <shar name> [-default] <url> [-title comment] <attribute name> [-exclude] [-filter [!]<val1> [!]<val2> ...]";    
    static String removeUsage = "\tArpUtil remove <arp name> [<shar name> [<url> [<attribute name>]]]";
    static String setAclUsage = "\tArpUtil setAcl <user> <acl> <arp name> [<shar name> [<url>]]";
    static String attrUsage = "\tArpUtil listAttributes <jar file name>";

	public static void main(String[] args) throws AAException {

		if (System.getProperty("log.config") != null) {
			PropertyConfigurator.configure(System.getProperty("log.config"));
		} else {
			BasicConfigurator.configure();
		}

		Properties props = new Properties();
		if (System.getProperty("arp.dir") != null) {
			props.setProperty(
				"edu.internet2.middleware.shibboleth.aa.FileArpRepository.Path",
				System.getProperty("arp.dir"));
		} else {
			props.setProperty("edu.internet2.middleware.shibboleth.aa.FileArpRepository.Path", ".");
		}
		arpFactory =
			ArpRepositoryFactory.getInstance(
				"edu.internet2.middleware.shibboleth.aa.FileArpRepository",
				props);

		//user = new KerberosPrincipal(System.getProperty("user.name"));
		user = new AA_Identity(System.getProperty("user.name"));

		log.info("Running as: (" + user + ").");

		String usage =
			"Usage:\n"
				+ listUsage
				+ "\nor\n"
				+ addUsage
				+ "\nor\n"
				+ removeUsage
				+ "\nor\n"
				+ setAclUsage
				+ "\nor\n"
				+ attrUsage;

		if (args.length < 2) {
			System.out.println(usage);
			return;
		}
		if (args[0].equalsIgnoreCase("list")) {
			doList(args);
		} else if (args[0].equalsIgnoreCase("add")) {
			doAdd(args);
		} else if (args[0].equalsIgnoreCase("remove")) {
			doRemove(args);
		} else if (args[0].equalsIgnoreCase("setAcl")) {
			doSetAcl(args);
		} else if (args[0].equalsIgnoreCase("listAttributes")) {
			doListAttributes(args);
		} else {
			System.out.println(usage);
		}
	}

    static void doList(String[] args){
	try{
	    int len = args.length;
	    if(len < 2){
		System.out.println("Usage:\n"+listUsage);		
		return;
	    }
	    String arpName = args[1];
	    DirContext ctx = null;
	    boolean acls = false;
	    if(len > 2){
		if(args[2].equalsIgnoreCase("-acls"))
		    acls = true;
		if(args[2].equalsIgnoreCase("-dir")){
		    if(len < 4){
			System.out.println("Usage:\n"+listUsage);
			return;
		    }else{
			ctx = getUserContext(args);
		    }
		    if(ctx == null){
			System.out.println("Failed to get Directory Context.");
			return;
		    }
		}
	    }

	    Arp arp = arpFactory.lookupArp(arpName, false);
	    if(arp.isNew() == true){
		System.out.println("Arp not Found: "+arpName);
	    }
	    System.out.println("ARP: "+arp);
	    if(acls)
		System.out.println("ACL: "+arp.getAcl());
	    ArpShar[] shars = arp.getShars();

	    for(int i=0; i < shars.length; i++){
		System.out.println("\tSHAR: "+shars[i]);
		if(acls)
		    System.out.println("\tACL: "+shars[i].getAcl());
		ArpResource[] resources = shars[i].getResources();
		for(int j=0; j < resources.length; j++){
		    System.out.println("\t\tURL: "+resources[j]);
		    if(resources[j].getComment() != null)
			System.out.println("\t\tTITLE: "+resources[j].getComment());
		    if(acls)
			System.out.println("\t\tACL: "+resources[j].getAcl());
		    ArpAttribute[] attributes = resources[j].getAttributes();
		    for(int k=0; k < attributes.length; k++){
			System.out.print("\t\t\t"+attributes[k]);
			if(ctx != null){
			    Attribute attr = attributes[k].getDirAttribute(ctx, true);
			    System.out.print(" VALUE(S): ");
			    if(attr == null)
				System.out.print("NULL");
			    else
				for(Enumeration en = attr.getAll();
				    en.hasMoreElements();)
				    System.out.print(en.nextElement()+" ");
							
			}
			ArpFilter filter = attributes[k].getFilter();
			if(filter == null)
			    System.out.println("");
			else
			    System.out.println(" FILTER: "+filter);
		    }
		}
	    }
	}catch(Exception e){
	    e.printStackTrace();
	}
    }

    static void doAdd(String[] args){

	if(args.length < 5){
	    System.out.println("Usage:\n"+addUsage);
	    return;
	}
	int i = 1;
	boolean isAdmin = false;
	boolean isDefault = false;
	boolean doExclude = false;
	boolean hasFilter = false;
	boolean showTitle = false;
	String resourceName = null;
	String sharName = null;
	String attrName = null;
	String title = null;

	String arpName = args[i++];
	if(args[i].equalsIgnoreCase("-admin")){
	    isAdmin = true;
	    i++;
	}
	
	sharName = args[i++];
	if(args[i].equalsIgnoreCase("-default")){
	    isDefault = true;
	    i++;
	}
	
	if(i < args.length)
	    resourceName = args[i++];

	if(i < args.length && args[i].equalsIgnoreCase("-title")){
	    showTitle = true;
	    i++;
	    if(i <args.length)
		title = args[i++];
	}
	
	if(i < args.length)
	    attrName = args[i++];
	if(i < args.length && args[i].equalsIgnoreCase("-exclude")){
	    doExclude = true;
	    i++;
	}
	if(i < args.length && args[i].equalsIgnoreCase("-filter")){
	    if(doExclude){
		System.out.println("Cannot set filter for an excluded attribute");
		return;
	    }
	    hasFilter = true;
	    i++;
	}

	if(arpName == null || arpName.startsWith("-") ||
	   sharName == null || sharName.startsWith("-") ||
	   resourceName == null || resourceName.startsWith("-") ||
	   attrName == null || attrName.startsWith("-")){
	    System.out.println("Usage:\n"+addUsage);
	    return;
	}

	if((isDefault || doExclude) && (!isAdmin)){
	    System.out.println("-admin must be specified for -default or -exclude");
	    return;
	}
	  
	log.debug("Admin arp?: " + isAdmin);
	log.debug("Default arp?: " + isDefault);
	log.debug("Resource name: " + resourceName);
	log.debug("SHAR name: " + sharName);
	log.debug("Attribute name: " + attrName);
	

	try{
	    Arp arp = arpFactory.lookupArp(arpName, isAdmin);
	    if (arp == null) {
	    	arp = new Arp(arpName, isAdmin);
			arp.setNew(true);
			arp.setLastRead(new Date());
			log.info("Creating new ARP.");
	    } else {
	    	log.info("Editing existing ARP.");
	    }
	    
	    ArpShar s = arp.getShar(sharName);

	    if(s == null)
		s = new ArpShar(sharName, isDefault);
	    ArpResource r = s.getResource(resourceName);
	    if(r == null)
		r = new ArpResource(resourceName, title);
	    ArpAttribute a = r.getAttribute(attrName);
	    if(a == null)
		a = new ArpAttribute(attrName, doExclude);

	    if(hasFilter){
		ArpFilter filter = new ArpFilter();
		while(i < args.length){
		    String val = args[i++];
		    boolean include = false;
		    if(val.startsWith("!")){
			val = val.substring(1);
			include = true;
		    }
		    ArpFilterValue valFilter = new ArpFilterValue(val, include);
		    filter.addAFilterValue(valFilter, true);
		}
		a.setFilter(filter, true);
	    }
		       
	    r.addAnAttribute(a);
	    s.addAResource(r);
	    arp.addAShar(s);
	    arpFactory.update(arp);
	}catch(AAPermissionException pe){
	    System.out.println("Permission denied: "+pe);
	}catch(Exception e){
	    e.printStackTrace();
	}
    }

    static void doRemove(String[] args){

	if(args.length < 2){
		log.fatal("Not enough arguments.");
	    System.out.println("Usage:\n"+removeUsage);
	    return;
	}
	int i = 1;
	String arpName = args[i++];
	String resourceName = null;
	String sharName = null;
	String attrName = null;

	if(i < args.length)
	    sharName = args[i++];
	if(i < args.length)
	    resourceName = args[i++];
	if(i < args.length)
	    attrName = args[i++];

	if(arpName.startsWith("-") ||
	   (sharName != null && sharName.startsWith("-")) ||
	   (resourceName != null && resourceName.startsWith("-")) ||
	   (attrName != null && attrName.startsWith("-"))){
	   	log.fatal("Unrecognized argument.");
	    System.out.println("Usage:\n"+removeUsage);
	    return;
	}

	try{
	    Arp arp = arpFactory.lookupArp(arpName, false/* does not matter here */);
	    if(arp.isNew()){
		System.out.println("ARP not found: "+arp);
		return;
	    }
	    if(sharName == null){
		// remove the whole arp
		arpFactory.remove(arp);
		return;
	    }
	    ArpShar s = arp.getShar(sharName);
	    if(s == null){
		System.out.println("SHAR not found for this ARP: "+sharName);
		return;
	    }
	    if(resourceName == null){
		// remove the whole shar
		arp.removeAShar(sharName);
		arpFactory.update(arp);
		return;
	    }
	    ArpResource r = s.getResource(resourceName);
	    if(r == null){
		System.out.println("URL not found for this SHAR: "+resourceName);
		return;
	    }
	    if(attrName == null){
		// remove the whole resource
		s.removeAResource(resourceName);
		arpFactory.update(arp);
		return;
	    }
	    ArpAttribute a = r.getAttribute(attrName);
	    if(a == null){
		System.out.println("ATTRIBUTE not found for this URL: "+attrName);
		return;
	    }
	    r.removeAnAttribute(attrName);
	    arpFactory.update(arp);
	}catch(AAPermissionException pe){
	    System.out.println("Permission denied: "+pe);
	}catch(Exception e){
	    e.printStackTrace();
	}	
    }

    public static void doSetAcl(String[] args){
	int len = args.length;
	if(len < 4){
	    System.out.println("Usage:\n"+setAclUsage);
	    return;
	}
	int i = 1;
	String user = args[i++];
	String acl = args[i++];
	String arpName = args[i++];

	String resourceName = null;
	String sharName = null;

	if(i < args.length)
	    sharName = args[i++];
	if(i < args.length)
	    resourceName = args[i++];

	if(arpName.startsWith("-") ||
	   (sharName != null && sharName.startsWith("-")) ||
	   (resourceName != null && resourceName.startsWith("-"))){
	    System.out.println("Usage:\n"+setAclUsage);
	    return;
	}
	if(acl.equalsIgnoreCase("LOOKUP") ||
	   acl.equalsIgnoreCase("INSERT") ||
	   acl.equalsIgnoreCase("READ") ||
	   acl.equalsIgnoreCase("WRITE") ||
	   acl.equalsIgnoreCase("DELETE") ||
	   acl.equalsIgnoreCase("ALL"))
	    ;
	else{
	    System.out.println("Invalid ACL : "+acl);
	    System.out.println("Valid ACLs are: LOOKUP, INSERT, READ, WRITE, DELETE, and ALL");
	    return;
	}

	  

	try{
	    Arp arp = arpFactory.lookupArp(arpName, false/* does not matter here */);
	    if(arp.isNew()){
		System.out.println("ARP not found: "+arp);
		return;
	    }
	    if(sharName == null){
		// set ACL fo the whole arp
		arp.setAcl(user, acl);
		arpFactory.update(arp);
		return;
	    }
	    ArpShar s = arp.getShar(sharName);
	    if(s == null){
		System.out.println("SHAR not found for this ARP: "+sharName);
		return;
	    }
	    if(resourceName == null){
		// set ACL the whole shar
		s.setAcl(user, acl);
		arpFactory.update(arp);
		return;
	    }
	    ArpResource r = s.getResource(resourceName);
	    if(r == null){
		System.out.println("URL not found for this SHAR: "+resourceName);
		return;
	    }
	    // set ACL the resource
	    r.setAcl(user, acl);
	    arpFactory.update(arp);
	    return;
	}catch(AAPermissionException pe){
	    System.out.println("Permission denied: "+pe);
	}catch(Exception e){
	    e.printStackTrace();
	}
    }

    static void doListAttributes(String[] args){
	try{
	    int len = args.length;
	    if(len < 2){
		System.out.println("Usage:\n"+attrUsage);		
		return;
	    }
	    String jarFile = args[1];
	    AAAttributes aaa = new AAAttributes(jarFile);
	    System.out.println("List of all known attributes:");
	    String[] list = aaa.list();
	    for(int i=0; i<list.length; i++)
		System.out.println("\t"+list[i]);
	}catch(Exception e){
	    e.printStackTrace();
	}
    }

    public static DirContext getUserContext(String[] args)
    throws Exception{

	if(args.length <5){
	    System.out.println("Usage:\n"+listUsage);
	    return null;
	}

	String dirUrl = args[3];
	String uid = args[4];
	
        Hashtable env = new Hashtable(11);

	env.put(Context.INITIAL_CONTEXT_FACTORY,
		"com.sun.jndi.ldap.LdapCtxFactory");
	env.put(Context.PROVIDER_URL, dirUrl);
	DirContext ctx = new InitialDirContext(env);
	return (DirContext)ctx.lookup("uid="+uid);
		
    }
	
}





