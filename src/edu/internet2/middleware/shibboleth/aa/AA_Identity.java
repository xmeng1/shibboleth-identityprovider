package edu.internet2.middleware.shibboleth.aa;

import java.security.*;
import java.io.*;

public class AA_Identity implements java.security.Principal, Serializable{

    String ident;

    public AA_Identity(String ident){
	this.ident = ident;
    }

    /////// Methods //////////

    public boolean equals(Object o){
	return (ident.equalsIgnoreCase(o.toString()));
    }

    public String getName(){
	return ident;
    }

    public String toString(){
	return ident;
    }
    public int hashCode(){
	return ident.hashCode();
    }
}





