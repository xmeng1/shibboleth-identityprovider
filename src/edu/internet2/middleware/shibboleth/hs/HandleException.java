package edu.internet2.middleware.shibboleth.hs;

import edu.internet2.middleware.shibboleth.*;
import edu.internet2.middleware.shibboleth.common.*;
import java.util.StringTokenizer;

/**
 *  Indicates an error with the Handle Server
 *
 * @author     Barbara Jensen
 * @created    March 6 2002
 */

public class HandleException extends Exception{
    /** SQL failure status code */
    public final static String SQL = "handle:SQL error";
    
    /** handle failure status code */
    public final static String ERR = "handle:general error";
    
    /* will create more codes later to better handle things */

    private String codes;

    /**
     *  Creates a new exception
     *
     * @param  codes  Zero or more dot-separated QNames
     * @param  s      The error message
     */
    public HandleException (String codes, String msg)
    {
        super(msg);
	this.codes = codes;
    }

    public  HandleException (String msg)
    {
        super(msg);
	this.codes = ERR;
    }

    public String[] getCodes()
    {
        if (codes == null || codes.length() == 0)
            return null;
        StringTokenizer tk = new StringTokenizer(codes, ".", false);
        int i = tk.countTokens();
        String[] ret = new String[i];
        for (i--; i >= 0; i--)
            ret[i] = tk.nextToken();
        return ret;
    }

}

