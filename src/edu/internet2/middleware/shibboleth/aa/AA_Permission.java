package aa;

import java.security.acl.*;
import java.io.*;
public class AA_Permission implements java.security.acl.Permission, Serializable{

    protected static int LOOKUP = 0;
    protected static int READ = 1;
    protected static int WRITE = 2;
    protected static int INSERT = 3;
    protected static int DELETE = 4;
    protected static int ALL = 5;

    protected static String names[] = {
	"LOOKUP",
	"READ",
	"WRITE",
	"INSERT",
	"DELETE",
	"ALL"};


    int permission;

    AA_Permission(int p){
	permission = p;
    }

    /////// Methods //////////

    public boolean equals(Object o){
	return (permission == ((AA_Permission)o).getIntVal());
    }

    public int getIntVal(){
	return permission;
    }

    public String toString(){
	return names[permission];
    }
    public int hashCode(){
	return permission+1;
    }
}





