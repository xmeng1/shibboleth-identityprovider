package edu.internet2.middleware.shibboleth.common;

import javax.xml.parsers.ParserConfigurationException;

import edu.internet2.middleware.shibboleth.common.XML.SchemaResolver;

/**
 *  Handles one-time library initialization
 *
 * @author     Scott Cantor
 * @created    May 18, 2002
 */
public class Init
{
    private static boolean initialized = false;

    /**  Initializes library */
    public static synchronized void init()
    {
        if (initialized)
            return;

        initialized = true;
        
        org.opensaml.Init.init();
        try
        {
            org.opensaml.XML.parserPool.registerExtension(XML.SHIB_NS, XML.SHIB_SCHEMA_ID, new XML.SchemaResolver());
        }
        catch (ParserConfigurationException e)
        {
            throw new RuntimeException("Init.init() unable to register extension schema");
        }
    }

    static
    {
        Init.init();
    }
}

