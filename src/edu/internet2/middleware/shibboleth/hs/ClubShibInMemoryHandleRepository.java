package edu.internet2.middleware.shibboleth.hs;

import java.util.*;
import javax.servlet.http.*;

public class ClubShibInMemoryHandleRepository extends HandleRepositoryFactory{

    final static String db = "HandleService";
    Hashtable handleHash; 

    public ClubShibInMemoryHandleRepository(HttpServlet HS) 
	throws HandleException 
    {
	handleHash = new Hashtable();
    }


    public HandleEntry getHandleEntry( String handle )
	throws HandleException
    {
	HandleEntry he = null;

	if (handle == null){
	    throw new HandleException(HandleException.ERR, "ClubShibInMemoryHandleRepository().getHandleEntry requires handle");
	}
	    
	he = (HandleEntry)handleHash.get( handle );

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

	handleHash.put( handle, he );

    }

    public String toHTMLString() 
	throws HandleException
    {
	String HTMLString = new String();
	
	return HTMLString;
    }
	
}
