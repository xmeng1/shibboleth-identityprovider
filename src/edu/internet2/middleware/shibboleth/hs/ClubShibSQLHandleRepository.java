package edu.internet2.middleware.shibboleth.hs

import java.util.*;
import java.sql.*;
import javax.servlet.http.*;

public class ClubShibSQLHandleRepository extends HandleRepositoryFactory{

    private Connection con;
    String DBdriver;
    String DBuser;
    String DBpass;
    String DBdomain;
    String DBurl;
    final static String db = "HandleService";

    public ClubShibSQLHandleRepository(HttpServlet HS) 
	throws HandleException 
    {
	DBdriver = HS.getInitParameter("DBdriver");
	DBuser = HS.getInitParameter("DBuser");
	DBpass = HS.getInitParameter("DBpass");
	DBdomain = HS.getInitParameter("DBdomain");
	DBurl = "jdbc:mysql://"+DBdomain+"/shib"+
	    "?user="+DBuser+"&password="+DBpass+"&autoReconnect=true";
	    
	try {
	    Class.forName(DBdriver);
	}
	catch (Exception ex) {
	    throw new HandleException(HandleException.SQL, ex.getMessage());
	}
	try {
	    con = DriverManager.getConnection(DBurl);
	} 
	catch (Exception ex) {
	    throw new HandleException(HandleException.SQL, ex.getMessage());
	}

    }

    public HandleEntry getHandleEntry( String handle )
	throws HandleException
    {
	HandleEntry he = null;

	if (handle == null){
	    throw new HandleException(HandleException.ERR, "ClubShibSQLHandleRepository() requires handle");
	}

        try{
            Statement st = con.createStatement();
            String query = "SELECT * FROM "+db+" WHERE handle=\""+handle+"\"";
            ResultSet rs = st.executeQuery(query);

	    if(rs == null)
		throw new HandleException(HandleException.ERR, "null result set for handle: "+handle);
	    
	    while (rs.next()) {
		he = new HandleEntry( rs.getString("handle"), 
				      rs.getString("username"),
				      rs.getString("authType"),
				      rs.getLong("authInstant"),
				      rs.getLong("expInstant"));
	    }
	    st.close();
	}
	catch (SQLException e) {
	    throw new HandleException(HandleException.SQL, e.getMessage());
        }
	if ( he == null ) 
	    throw new HandleException(HandleException.ERR, "getHandleEntry() cannot find matching record for handle: "+handle);
	else
	    return he;
    }
    

    public void insertHandleEntry( HandleEntry he )
	throws HandleException
    {
	if ( he == null ) { 
	    throw new HandleException(HandleException.ERR, "InsertHandle() requires HandleEntry arg");
	}

	String handle = he.getHandle();
	String username = he.getUsername();
	String authType = he.getAuthType();
	long authInstant = he.getAuthInstant();
	long expInstant = he.getExpInstant();

        try{
            Statement st = con.createStatement();
            String update = "INSERT INTO " +db+
                " VALUES ( \"" + handle +"\", \""+username+"\", \""+
		authType+"\", \""+ authInstant +"\", \""+
		expInstant+"\")";
            st.executeUpdate(update);
	    st.close();
        }
        catch (SQLException e) {
	    throw new HandleException(HandleException.SQL, e.getMessage());
        }
    }

    public String toHTMLString() 
	throws HandleException
    {
	String HTMLString = new String();
	
        try{
            Statement st = con.createStatement();
            String query = "SELECT * FROM "+db;
            ResultSet rs = st.executeQuery(query);
            HTMLString = "Server = "+DBdomain+"<br>"+
		"<table><tr><td><b>handle</b></td>"+
		"<td><b>username</b></td>"+
		"<td><b>authType</b></td>"+
		"<td><b>authInstant</b></td>"+
		"<td><b>expInstant</b></td></tr>";
            while (rs.next()) {
                String han = rs.getString(1);
                String uid = rs.getString(2);
                String authtype = rs.getString(3);
                String date_in = rs.getString(4);
                String date_exp = rs.getString(5);

                HTMLString += "<tr><td>"+han+"</td><td>"+uid+"</td>" +
		"<td>"+authtype+"</td>"+
                "<td>"+date_in+"</td>"+
                "<td>"+date_exp+"</td></tr>";
            }
	    st.close();

	    HTMLString += "</table>";
        }
        catch (SQLException e) {
	    throw new HandleException(HandleException.SQL, e.getMessage());
        }

	return HTMLString;
    }
    public void destroy() 
	throws HandleException
    {
	try {
	    con.close();
	}
	catch (SQLException e) {
	    throw new HandleException(HandleException.SQL, e.getMessage());
	}

    }	
	
}
