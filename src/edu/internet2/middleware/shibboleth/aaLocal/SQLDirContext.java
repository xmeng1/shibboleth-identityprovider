package edu.internet2.middleware.shibboleth.aaLocal;

import java.util.*;
import java.sql.*;
import javax.naming.*;
import javax.naming.directory.*;

public class SQLDirContext extends InitialDirContext{

    Connection con;
    String uid;
    String guid;
    Hashtable id2name;

    public SQLDirContext(Hashtable env)
	throws NamingException{

	String url = (String)env.get(Context.PROVIDER_URL);
	String driver = (String)env.get("SQL_DRIVER");
	String user = (String)env.get("SECURITY_PRINCIPAL");
	String passwd = (String)env.get("SECURITY_CREDENTIALS");
	uid = (String)env.get("USER_IDENTIFIER");
	if(url == null)
	    throw new NamingException("Context.PROVIDER_URL not provided");
	if(driver == null)
	    throw new NamingException("SQL_DRIVER is required");
	if(user == null)
	    throw new NamingException("SECURITY_PRINCIPAL is required");
	if(passwd == null)
	    throw new NamingException("SECURITY_CREDENTIALS is required");
	if(uid == null)
	    throw new NamingException("USER_IDENTIFIER is required");
	id2name = new Hashtable();



	try{
	    Class.forName(driver);
	    con = DriverManager.getConnection(url, user, passwd);
	    // get the small sql table and keep it as a hashtable for performance
	    Statement stmt = con.createStatement();
	    ResultSet rs = stmt.executeQuery("SELECT attr_id,attr_name from danr.person_attributes");	    
	    while(rs.next()){
		int i = rs.getInt("attr_id");
		String n = rs.getString("attr_name");
		id2name.put(new Integer(i), n);
	    }

	    // find the guid from uid
	    String guidQ1 = "SELECT guid from danr.person_attrib WHERE attr_id = ";
	    String guidQ2 = "(SELECT attr_id from danr.person_attributes where attr_name = 'cmuAndrewId')";
	    String guidQ3 = " AND attr_value = '"+uid+"'";


	    rs = stmt.executeQuery(guidQ1+guidQ2+guidQ3);
	    rs.next();
	    guid = rs.getString("GUID");
	}catch(Exception e){
	    throw new NamingException("Failed to create SQLDirContext: "+e);
	}
    }

    public Attributes getAttributes(String name,
				    String[] attrIds)
	throws NamingException {

	long aTime = System.currentTimeMillis();
	String q1 = "select attr_id,attr_value from danr.person_attrib where guid = '";
	String q2 = "' and attr_id = (select attr_id from danr.person_attributes where attr_name ='";
	String q3 = "')";
	StringBuffer buf = new StringBuffer(q1+guid+q2);
	BasicAttributes attrs = new BasicAttributes();
	try{
	    int len = attrIds.length;

	    String[] attrNames = new String[len];
	    System.arraycopy(attrIds, 0, attrNames, 0, len);
	    Arrays.sort(attrNames);

	    for(int i=0; i <len-1; i++)
		buf.append(attrIds[i] + "' OR attr_name ='");
	    buf.append(attrIds[len-1]);
	    buf.append(q3);

	    Statement stmt = con.createStatement();
	    ResultSet rs = stmt.executeQuery(buf.toString());	    

	    BasicAttribute[] attrArray = new BasicAttribute[len];
	    for(int i=0; i <len; i++)
		attrArray[i] = new BasicAttribute(attrIds[i]);

	    while(rs.next()){
		int anId = rs.getInt("attr_id");
		String aName = (String)id2name.get(new Integer(anId));
		Object value = rs.getObject("attr_value");
		int indx = Arrays.binarySearch(attrNames, aName);
		attrArray[indx].add(value);
	    }
	    
	    for(int i=0; i <len; i++)
		attrs.put(attrArray[i]);
	    System.out.print(" ("+(System.currentTimeMillis() - aTime)+" sec)");
	    return attrs;
	}catch(Exception e){
	    throw new NamingException("Failed to get Attributes: "+e);
	}
    }
}
