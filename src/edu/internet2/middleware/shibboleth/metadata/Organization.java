/*
 * Created on Feb 28, 2005
 *
 */
package edu.internet2.middleware.shibboleth.metadata;

import java.net.URL;

/**
 * @author Scott Cantor
 */
public interface Organization {

    public String getName();
    public String getName(String lang);
    
    public String getDisplayName();
    public String getDisplayName(String lang);

    public URL getURL();
    public URL getURL(String lang);
}
