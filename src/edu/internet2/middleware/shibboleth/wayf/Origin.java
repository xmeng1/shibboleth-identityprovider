package edu.internet2.middleware.shibboleth.wayf;

import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.StringTokenizer;

/**
 * This class represents an Origin site in the shibboleth parlance.
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */

public class Origin {

    private String name;
    private ArrayList aliases = new ArrayList();
    private String handleService;

    /**
     * Gets the handleService for this origin.
     * @return Returns a String
     */
    public String getHandleService() {
        return handleService;
    }

    /**
     * Sets the handleService for this origin.
     * @param handleService The handleService to set
     */
    public void setHandleService(String handleService) {
        this.handleService = handleService;
    }

    /**
     * Gets the origin name.
     * @return Returns a String
     */
    public String getName() {
        return name;
    }

    public String getUrlEncodedName() {

        return URLEncoder.encode(name);

    }

    /**
     * Sets a name for this origin.
     * @param name The name to set
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Gets all aliases for this origin.
     * @return Returns a String[]
     */
    public String[] getAliases() {
        return (String[]) aliases.toArray(new String[0]);
    }

    /**
     * Adds an alias for this origin.
     * @param alias The aliases to set
     */
    public void addAlias(String alias) {
        aliases.add(alias);
    }

    /**
     * Determines if a given string matches one of the registered names/aliases of this origin.
     * @param str The string to match on
     */
    public boolean isMatch(String str, WayfConfig config) {

        Enumeration input = new StringTokenizer(str);
        while (input.hasMoreElements()) {
            String currentToken = (String) input.nextElement();

            if (config.isIgnoredForMatch(currentToken)) {
                continue;
            }

            if (getName().toLowerCase().indexOf(currentToken.toLowerCase()) > -1) {
                return true;
            }
            Iterator aliasit = aliases.iterator();
            while (aliasit.hasNext()) {
                String alias = (String) aliasit.next();
                if (alias.toLowerCase().indexOf(currentToken.toLowerCase()) > -1) {
                    return true;
                }
            }

        }
        return false;
    }

}