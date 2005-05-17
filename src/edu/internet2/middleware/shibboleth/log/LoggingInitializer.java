/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met: Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials
 * provided with the distribution, if any, must include the following acknowledgment: "This product includes software
 * developed by the University Corporation for Advanced Internet Development <http://www.ucaid.edu>Internet2 Project.
 * Alternately, this acknowledegement may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear. Neither the name of Shibboleth nor the names of its contributors, nor Internet2, nor
 * the University Corporation for Advanced Internet Development, Inc., nor UCAID may be used to endorse or promote
 * products derived from this software without specific prior written permission. For written permission, please contact
 * shibboleth@shibboleth.org Products derived from this software may not be called Shibboleth, Internet2, UCAID, or the
 * University Corporation for Advanced Internet Development, nor may Shibboleth appear in their name, without prior
 * written permission of the University Corporation for Advanced Internet Development. THIS SOFTWARE IS PROVIDED BY THE
 * COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE
 * DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE. IN NO
 * EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC.
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.log;

import java.net.MalformedURLException;
import java.net.URL;

import org.apache.log4j.DailyRollingFileAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.PropertyConfigurator;
import org.apache.log4j.xml.DOMConfigurator;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import edu.internet2.middleware.shibboleth.common.ShibResource;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.idp.IdPConfig;

/**
 * A helper class for configuring the the IdP transaction log, general system log, and any logs specified in a Log4J
 * configuration file.
 * <p>
 * The IdP transaction log with the name <code>Shibboleth-TRANSACTION</code> and should be used to track an
 * individuals path through the IdP. It's default logging level is <code>INFO</code>.
 * <p>
 * The general system log logs messages from any class in either the <code>edu.internet2.middleware.shibboleth</code>
 * package or the <code>org.opensaml</code> package. It's default logging level is <code>WARN</code>
 * <p>
 * All logs are configured through information found in the IdP XML configuration file.
 * 
 * @author Chad La Joie
 */
public class LoggingInitializer {

	/**
	 * Log message layout pattern for the transaction log
	 */
	private static String txLogLayoutPattern = "%d{ISO8601} %m%n";

	/**
	 * Date pattern used at the end of the transaction log filename
	 */
	private static String txLogAppenderDatePattern = "'.'yyyy-MM-dd";

	/**
	 * Log message layout pattern for the general system log
	 */
	private static String sysLogLayoutPattern = "%d{ISO8601} %-5p %-41X{serviceId} - %m%n";

	/**
	 * Date pattern used at the end of the general system log filename
	 */
	private static String sysLogAppenderDatePattern = "'.'yyyy-MM-dd";

	/**
	 * Initializes the Log4J logging framework.
	 * 
	 * @param configuration
	 *            logging configuration element from the IdP XML configuration file
	 * @throws ShibbolethConfigurationException
	 *             thrown if there is a problem configuring the logs
	 */
	public static void initializeLogging(Element configuration) throws ShibbolethConfigurationException {

		NodeList txLogElems = configuration.getElementsByTagNameNS(IdPConfig.configNameSpace, "TransactionLog");
		if (txLogElems.getLength() > 0) {
			if (txLogElems.getLength() > 1) {
				System.err.println("WARNING: More than one TransactionLog element detected in IdP logging "
						+ "configuration, only the first one will be used.");
			}
			Element txLogConfig = (Element) txLogElems.item(0);
			configureTransactionLog(txLogConfig);
		}

		NodeList sysLogElems = configuration.getElementsByTagNameNS(IdPConfig.configNameSpace, "ErrorLog");
		if (sysLogElems.getLength() > 0) {
			if (sysLogElems.getLength() > 1) {
				System.err.println("WARNING: More than one ErrorLog element detected in IdP logging configuration, "
						+ "only the first one will be used.");
			}
			Element sysLogConfig = (Element) sysLogElems.item(0);
			configureSystemLog(sysLogConfig);
		}

		NodeList log4jElems = configuration.getElementsByTagNameNS(IdPConfig.configNameSpace, "Log4JConfig");
		if (log4jElems.getLength() > 0) {
			if (log4jElems.getLength() > 1) {
				System.err.println("WARNING: More than one Log4JConfig element detected in IdP logging configuration, "
						+ "only the first one will be used.");
			}
			Element log4jConfig = (Element) log4jElems.item(0);
			configureLog4J(log4jConfig);
		}
	}

	/**
	 * Configures the transaction log.
	 * 
	 * @param configuration
	 *            the TransactionLog element from the IdP XML logging configuration
	 * @throws ShibbolethConfigurationException
	 *             thrown if there is a problem configuring the logs
	 */
	private static void configureTransactionLog(Element configuration) throws ShibbolethConfigurationException {

		NamedNodeMap attributes = configuration.getAttributes();

		String location = attributes.getNamedItem("location").getNodeValue();
		if (location == null) { throw new ShibbolethConfigurationException(
				"No log file location attribute specified in TransactionLog element"); }

		DailyRollingFileAppender appender = null;
		try {
			String logPath = new ShibResource(location, LoggingInitializer.class).getFile().getCanonicalPath();
			PatternLayout messageLayout = new PatternLayout(txLogLayoutPattern);

			appender = new DailyRollingFileAppender(messageLayout, logPath, txLogAppenderDatePattern);
			appender.setName("shibboleth-transaction");
		} catch (Exception e) {
			throw new ShibbolethConfigurationException("<TransactionLog location=\"" + location
					+ "\">: error creating DailyRollingFileAppender: " + e);
		}

		Level level = Level.INFO;
		if (attributes.getNamedItem("level") != null) {
			level = Level.toLevel(attributes.getNamedItem("level").getNodeValue());
		}

		Logger log = Logger.getLogger("Shibboleth-TRANSACTION");
		log.setAdditivity(false); // do not want parent's messages
		log.setLevel(level);
		log.addAppender(appender);
	}

	/**
	 * Configures the system-wide IdP log.
	 * 
	 * @param configuration
	 *            the ErrorLog element from the IdP XML logging configuration
	 * @throws ShibbolethConfigurationException
	 *             thrown if there is a problem configuring the logs
	 */
	private static void configureSystemLog(Element configuration) throws ShibbolethConfigurationException {

		NamedNodeMap attributes = configuration.getAttributes();

		String location = attributes.getNamedItem("location").getNodeValue();
		if (location == null) { throw new ShibbolethConfigurationException(
				"No log file location attribute specified in ErrorLog element"); }

		DailyRollingFileAppender appender = null;
		try {
			String logPath = new ShibResource(location, LoggingInitializer.class).getFile().getCanonicalPath();
			PatternLayout messageLayout = new PatternLayout(sysLogLayoutPattern);

			appender = new DailyRollingFileAppender(messageLayout, logPath, sysLogAppenderDatePattern);
			appender.setName("shibboleth-error");
		} catch (Exception e) { // catch any exception
			throw new ShibbolethConfigurationException("<ErrorLog location=\"" + location
					+ "\">: error creating DailyRollingFileAppender: " + e);
		}

		Level level = Level.WARN;
		if (attributes.getNamedItem("level") != null) {
			level = Level.toLevel(attributes.getNamedItem("level").getNodeValue());
		}

		Logger shibLog = Logger.getLogger("edu.internet2.middleware.shibboleth");
		shibLog.setLevel(level);
		shibLog.addAppender(appender);

		Logger openSAMLLog = Logger.getLogger("org.opensaml");
		openSAMLLog.setLevel(level);
		openSAMLLog.addAppender(appender);
	}

	/**
	 * Configures Log4J by way of a Log4J specific configuration file.
	 * 
	 * @param configuration
	 *            the Log4JConfig element from the IdP XML logging configuration
	 * @throws ShibbolethConfigurationException
	 *             thrown if there is a problem configuring the logs
	 */
	private static void configureLog4J(Element configuration) throws ShibbolethConfigurationException {

		NamedNodeMap attributes = configuration.getAttributes();

		String location = attributes.getNamedItem("location").getNodeValue();
		if (location == null) { throw new ShibbolethConfigurationException(
				"No configuration file location attribute specified in Log4JConfig element"); }

		String type = null;
		Node typeNode = attributes.getNamedItem("type");
		if (typeNode != null) {
			type = typeNode.getNodeValue();
		}

		URL url;
		try {
			url = new URL(location);
		} catch (MalformedURLException e) {
			throw new ShibbolethConfigurationException("<Log4JConfig location=\"" + location + "\">: not a valid URL: "
					+ e);
		}

		if (type == null || "properties".equals(type)) {
			PropertyConfigurator.configure(url);
		} else if ("xml".equals(type)) {
			DOMConfigurator.configure(url);
		}
	}
}
