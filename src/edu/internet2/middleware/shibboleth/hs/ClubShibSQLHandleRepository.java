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

package edu.internet2.middleware.shibboleth.hs;

import java.util.*;
import java.sql.*;
import javax.servlet.*;
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
	ServletConfig sc = HS.getServletConfig();
	ServletContext sctx = sc.getServletContext();
	DBdriver = sctx.getInitParameter("DBdriver");
	DBuser = sctx.getInitParameter("DBuser");
	DBpass = sctx.getInitParameter("DBpass");
	DBdomain = sctx.getInitParameter("DBdomain");
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
		throw new HandleException("null result set for handle: "+handle);
	    
	    while (rs.next()) {
		he = new HandleEntry( rs.getString("handle"), 
				      rs.getString("username"),
				      rs.getString("authType"),
				      rs.getLong("authInstant"),
				      rs.getLong("expInstant"));
	    }
	    st.close();
	}
	catch (SQLException ex) {
	    throw new HandleException(ex.getMessage());
        }
	if ( he == null ) 
	    throw new HandleException("getHandleEntry() cannot find matching record for handle: "+handle);
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
	    throw new HandleException(e.getMessage());
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
