package edu.internet2.middleware.shibboleth.aa;

/**
 *  Attribute Authority & Release Policy
 *  General Exception for AA problems
 *
 * @author     Parviz Dousti (dousti@cmu.edu)
 * @created    June, 2002
 */


public class AAException extends Exception{
    String msg;
    public AAException(String s){
	msg = s;
    }
    public String toString(){
	return msg;
    }
}
