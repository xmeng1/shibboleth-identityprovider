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

package edu.internet2.middleware.shibboleth.log;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.File;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.apache.log4j.Logger;
import org.apache.log4j.Level;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.PropertyConfigurator;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.RollingFileAppender;
import org.apache.log4j.LogManager;
import org.apache.log4j.xml.DOMConfigurator;

import org.apache.xml.security.Init;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.NamedNodeMap;

import edu.internet2.middleware.shibboleth.common.OriginConfig;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.common.ShibbolethOriginConfig;
import edu.internet2.middleware.shibboleth.common.ShibResource;

/**
 * {@link ServletContextListener} used to configure logging for other components.
 * 
 * @author Walter Hoehn
 * @author Noah Levitt
 */
public class LoggingContextListener implements ServletContextListener {

	private static Logger log = Logger.getLogger(LoggingContextListener.class.getName());

	// tomcat calls this before the servlet init()s, but is that guaranteed?
	public void contextInitialized(ServletContextEvent sce)
	{
		ConsoleAppender rootAppender = new ConsoleAppender();
		rootAppender.setWriter(new PrintWriter(System.out));
		rootAppender.setName("stdout");
		Logger.getRootLogger().addAppender(rootAppender);

		// rootAppender.setLayout(new PatternLayout("%-5p %-41X{serviceId} %d{ISO8601} (%c:%L) - %m%n")); 
		// Logger.getRootLogger().setLevel((Level) Level.DEBUG);
		Logger.getRootLogger().setLevel((Level) Level.INFO);
		rootAppender.setLayout(new PatternLayout("%d{ISO8601} %-5p %-41X{serviceId} - %m%n"));

		Logger.getLogger("org.apache.xml.security").setLevel((Level) Level.OFF);
		Logger.getLogger("org.opensaml").setLevel((Level) Level.OFF);

		//Silliness to get around xmlsec doing its own configuration, ie: we might need to override it
		Init.init();

		try {
			Document originConfig = OriginConfig.getOriginConfig(sce.getServletContext());
			loadConfiguration(originConfig);
		} 
                catch (ShibbolethConfigurationException e) {
			sce.getServletContext().log("Problem setting up logging.", e);
			log.fatal("Problem setting up logging: " + e);
			throw new Error("Problem setting up logging: " + e);  // XXX
		}

		log.info("Logger initialized.");
	}

	public void contextDestroyed(ServletContextEvent sce)
	{
            log.info("Shutting down logging infrastructure.");
            LogManager.shutdown();
	}

	protected void loadConfiguration(Document originConfig) throws ShibbolethConfigurationException
	{
		NodeList itemElements = originConfig.getDocumentElement().getElementsByTagNameNS(ShibbolethOriginConfig.originConfigNamespace, "Logging");
		if (itemElements.getLength() > 1) 
		{
			log.warn("Encountered multiple <Logging> configuration elements. Using first one.");
		}

		if (itemElements.getLength() >= 1) 
		{
			Node loggingNode = itemElements.item(0);
			Node errorLogNode = null;

			for (int i = 0; i < loggingNode.getChildNodes().getLength(); i++)
			{
				Node node = loggingNode.getChildNodes().item(i);

				if ("Log4JConfig".equals(node.getNodeName()))
				{
					doLog4JConfig(node);
				}
				else if ("TransactionLog".equals(node.getNodeName()))
				{
					configureTransactionLog(node);
				}
				else if ("ErrorLog".equals(node.getNodeName()))
				{
					// make sure we do ErrorLog after TransactionLog so that the transaction log
					// initialization info always gets logged in the same place
					errorLogNode = node;
				}
			}

			if (errorLogNode != null)
			{
				configureErrorLog(errorLogNode);
			}
		}
	}

	// location should be a "file:/" uri
	private RollingFileAppender makeRollingFileAppender(String location, String pattern) throws ShibbolethConfigurationException
	{
		try {
			String logPath = new ShibResource(location, LoggingContextListener.class).getFile().getCanonicalPath();
			RollingFileAppender appender = new RollingFileAppender(new PatternLayout(pattern), logPath);

			appender.setMaximumFileSize(1024*1024);        // 1 megabyte
			appender.setMaxBackupIndex(Integer.MAX_VALUE); // imho we should not delete any log files

			return appender;
		}
		catch (IOException e) {
			log.fatal("<TransactionLog location=\"" + location + "\">: error creating RollingFileAppender: " + e);
			throw new ShibbolethConfigurationException("<TransactionLog location=\"" + location + "\">: error creating RollingFileAppender: " + e);
		}
	}

	private void configureErrorLog(Node node) throws ShibbolethConfigurationException
	{
		NamedNodeMap attributes = node.getAttributes();

		/* schema check should catch if location is missing, NullPointerException here if not */
		String location = attributes.getNamedItem("location").getNodeValue();
		RollingFileAppender appender = makeRollingFileAppender(location, "%d{ISO8601} %-5p %-41X{serviceId} - %m%n");

		appender.setName("error");
		appender.setMaxBackupIndex(Integer.MAX_VALUE); // imho we should not delete any log files

		Level level = (Level) Level.WARN;
		if (attributes.getNamedItem("level") != null)
		{
			log.info("Setting log level to " + attributes.getNamedItem("level").getNodeValue());
			level = Level.toLevel(attributes.getNamedItem("level").getNodeValue());
			Logger.getRootLogger().setLevel(level);
		}

		// log this before switching levels
		log.info("Switching logging to " + appender.getFile());
		Logger.getRootLogger().removeAllAppenders();
		Logger.getRootLogger().addAppender(appender);

		Logger.getRootLogger().setLevel(level);
	}

	private void configureTransactionLog(Node node) throws ShibbolethConfigurationException
	{
		NamedNodeMap attributes = node.getAttributes();

		// schema check should catch if location is missing, NullPointerException here if not
		String location = attributes.getNamedItem("location").getNodeValue();
		RollingFileAppender appender = makeRollingFileAppender(location, "%d{ISO8601} %m%n");
		appender.setName("transaction");

		Logger log = Logger.getLogger("Shibboleth-TRANSACTION");
		log.setAdditivity(false);         // do not want parent's messages
		log.setLevel((Level) Level.INFO); // all messages to this log are INFO

		// log.removeAllAppenders(); // imho we want these messages to appear in the "error" log if level >= INFO
		log.addAppender(appender);
	}

	private void doLog4JConfig(Node node) throws ShibbolethConfigurationException
	{
		NamedNodeMap attributes = node.getAttributes();

		// schema check should catch if location is missing, NullPointerException here if not
		String location = attributes.getNamedItem("location").getNodeValue();

		String type = null;
		if (attributes.getNamedItem("type") != null) 
		{
			type = attributes.getNamedItem("type").getNodeValue();
		}

		URL url;
		try {
			url = new URL(location);
		}
		catch (MalformedURLException e) {
			log.fatal("<Log4JConfig location=\"" + location + "\">: not a valid URL: " + e);
			throw new ShibbolethConfigurationException("<Log4JConfig location=\"" + location + "\">: not a valid URL: " + e);
		}

		if (type == null || "properties".equals(type))
		{
			log.info("Using Properties log4j configuration from " + url);
			PropertyConfigurator.configure(url);
		}
		else if ("xml".equals(type))
		{
			log.info("Using XML log4j configuration from " + url);
			DOMConfigurator.configure(url);
		}
	}
}

