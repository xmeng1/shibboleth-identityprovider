package edu.internet2.middleware.shibboleth.aa;

public class AAException extends Exception{
    String msg;
    public AAException(String s){
	msg = s;
    }
    public String toString(){
	return msg;
    }
}
