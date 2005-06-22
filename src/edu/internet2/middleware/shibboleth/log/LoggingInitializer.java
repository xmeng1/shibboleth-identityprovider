/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.log;

import java.io.IOException;

import org.apache.log4j.ConsoleAppender;
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
     * The log file extension
     */
    private static String logFileExtension = ".log";
    
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
		} else {
			configureTransactionLog();
		}

		NodeList sysLogElems = configuration.getElementsByTagNameNS(IdPConfig.configNameSpace, "ErrorLog");
		if (sysLogElems.getLength() > 0) {
			if (sysLogElems.getLength() > 1) {
				System.err.println("WARNING: More than one ErrorLog element detected in IdP logging configuration, "
						+ "only the first one will be used.");
			}
			Element sysLogConfig = (Element) sysLogElems.item(0);
			configureSystemLog(sysLogConfig);
		} else {
			configureSystemLog();
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
	 * Initialize the logs for the Shibboleth-TRANSACTION log, edu.internet2.middleware.shibboleth, and org.opensaml
	 * logs. Output is directed to the standard out with the the transaction log at INFO level and the remainder at
	 * warn.
	 */
	public static void initializeLogging() {

		configureTransactionLog();
		configureSystemLog();
	}

	/**
	 * Configured the transaction log to log to the console at INFO level.
	 */
	private static void configureTransactionLog() {

		ConsoleAppender appender = new ConsoleAppender(new PatternLayout(txLogLayoutPattern),
				ConsoleAppender.SYSTEM_OUT);
		Logger log = Logger.getLogger("Shibboleth-TRANSACTION");
		log.setAdditivity(false); // do not want parent's messages
		log.setLevel(Level.INFO);
		log.addAppender(appender);
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

		RollingFileAppender appender = null;
		try {
			String logPath = new ShibResource(location, LoggingInitializer.class).getFile().getCanonicalPath();
			PatternLayout messageLayout = new PatternLayout(txLogLayoutPattern);

			appender = new RollingFileAppender(messageLayout, logPath, txLogAppenderDatePattern, logFileExtension);
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
	 * Configures the standard system log to log messages from edu.internet2.middleware.shibboleth and org.opensaml to
	 * the console at WARN level.
	 */
	private static void configureSystemLog() {

		ConsoleAppender appender = new ConsoleAppender(new PatternLayout(sysLogLayoutPattern),
				ConsoleAppender.SYSTEM_OUT);
		Logger shibLog = Logger.getLogger("edu.internet2.middleware.shibboleth");
		shibLog.setLevel(Level.WARN);
		shibLog.addAppender(appender);

		Logger openSAMLLog = Logger.getLogger("org.opensaml");
		openSAMLLog.setLevel(Level.WARN);
		openSAMLLog.addAppender(appender);
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

		RollingFileAppender appender = null;
		try {
			String logPath = new ShibResource(location, LoggingInitializer.class).getFile().getCanonicalPath();
			PatternLayout messageLayout = new PatternLayout(sysLogLayoutPattern);

			appender = new RollingFileAppender(messageLayout, logPath, sysLogAppenderDatePattern, logFileExtension);
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

		ShibResource log4jConfig;
		try {
			log4jConfig = new ShibResource(location);
			if (type == null || "properties".equals(type)) {
				PropertyConfigurator.configure(log4jConfig.getURL());
			} else if ("xml".equals(type)) {
				DOMConfigurator.configure(log4jConfig.getURL());
			} else {
				throw new ShibbolethConfigurationException(
						"<Log4JConfig (type) attribute must be one of \"xml\" or \"properties\".");
			}
		} catch (IOException e) {
			throw new ShibbolethConfigurationException("<Log4JConfig location=\"" + location + "\">: not a valid URL: "
					+ e);
		}

	}
}