package aa;

//import aa.*;
import java.io.*;
import java.util.*;
import java.util.zip.*;
import java.util.jar.*;

/**
 * A class for managing local attributes
 */
public class AAAttributes{

    Class[] attrClasses = new Class[1];

    /**
     * Sole constructor. Takes a directory name in the local file system
     * where attribute classes reside
     */

    public AAAttributes(String jarFileName)
	throws AAException{

	try{

	    JarFile jf = new JarFile(jarFileName);
	    Vector attrs = new Vector();
	    Enumeration en = jf.entries();
	    while(en.hasMoreElements()){
		JarEntry je = (JarEntry)en.nextElement();
		String filename = (String)je.getName();
		if(filename.endsWith(".class")){
		    String name = filename.substring(0, filename.lastIndexOf(".class"));
		    Class attr = Class.forName(name);
		    attrs.add(attr);
		}
	    }
	    attrClasses = (Class[])attrs.toArray(attrClasses);
	}catch(Exception e){
	    throw new AAException("Failed to get the list of attribute classes: "+e);
	}
    }


    public Class[] listClasses(){
	return attrClasses;
    }

    public String[] list(){
	String[] a = new String[attrClasses.length];
	for(int i=0; i<a.length; i++){
	    a[i] = attrClasses[i].getName();
	}
	return a;
    }
}
