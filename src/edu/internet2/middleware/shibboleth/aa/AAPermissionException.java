package edu.internet2.middleware.shibboleth.aa;

/**
 *  Attribute Authority & Release Policy
 *  Any Permission Problem accessing ARPs
 *
 * @author     Parviz Dousti (dousti@cmu.edu)
 * @created    June, 2002
 */


public class AAPermissionException extends Exception{
    String msg;
    AAPermissionException(String s){
	msg = s;
    }
    public String toString(){
	return msg;
    }
}
