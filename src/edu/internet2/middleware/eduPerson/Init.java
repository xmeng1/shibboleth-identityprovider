package edu.internet2.middleware.eduPerson;

import javax.xml.parsers.ParserConfigurationException;

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
        
        edu.internet2.middleware.shibboleth.common.Init.init();
        try
        {
            org.opensaml.XML.parserPool.registerExtension(XML.EDUPERSON_NS, XML.EDUPERSON_SCHEMA_ID, new XML.SchemaResolver());
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

