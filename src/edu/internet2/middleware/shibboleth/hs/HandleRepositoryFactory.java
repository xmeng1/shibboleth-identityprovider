package edu.internet2.middleware.shibboleth.hs;

import javax.servlet.http.*;
import edu.internet2.middleware.shibboleth.*;
import edu.internet2.middleware.shibboleth.common.*;

/**
 *  Used by Shibboleth Handle Service and Attribute Authority to build a repository object
 */
public abstract class HandleRepositoryFactory
{
    /**  Array of policy URI(s) (HS and SHIRE) */
    protected String[] policies;
    protected String SQL = "SQL";
    protected String MEMORY = "MEMORY";

    public HandleRepositoryFactory()
    {
    }

    public static HandleRepositoryFactory getInstance(String policy, 
						      String repository,
						      HttpServlet HS)
        throws HandleException {

	if (policy.equalsIgnoreCase( Constants.POLICY_CLUBSHIB )) {
	    if (repository.equalsIgnoreCase( "SQL" )) {
		return new ClubShibSQLHandleRepository(HS);
	    } else if (repository.equalsIgnoreCase( "MEMORY" )) {
		return new ClubShibInMemoryHandleRepository(HS);
	    } else {
		throw new HandleException("Unspecified repository type.");
	    }
	}else{
	    throw new HandleException("Unsupported policy found.");
	}
    }

    public abstract HandleEntry getHandleEntry(String handle)
	throws HandleException;

    public abstract  void insertHandleEntry(HandleEntry he)
	throws HandleException;
    
    /* for debugging purposes only */
    public abstract String toHTMLString()
        throws HandleException;

}

