package aa;

import java.io.*;
public class ArpFilterValue implements Serializable{


    // Associations
    protected Object value;
    protected boolean include;


    // Constructor
    public ArpFilterValue(Object value, boolean include){
	this.value = value;
	this.include = include;
    }

    // Operations

    public boolean mustInclude(){
	return include; 
    }

    public Object getValue(){
	return value;
    }
    
    public boolean equlas(Object afv){
	return value.equals(((ArpFilterValue)afv).getValue());
    }

    public String toString(){
	return value+(include?"(include)":"");
    }

} /* end class ArpFilterValue */
