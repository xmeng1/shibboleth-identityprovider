package edu.internet2.middleware.shibboleth.log;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.apache.xml.security.Init;

/**
 * 
 * Servlet used to configure logging for other components.
 * 
 * @author Walter Hoehn
 *
 */
public class LogServ extends HttpServlet {

	private static Logger log = Logger.getLogger(LogServ.class.getName());

	/**
	 * @see javax.servlet.GenericServlet#init()
	 */
	public void init() throws ServletException {

		super.init();
		//Silliness to get around xmlsec doing its own configuration, ie: we might need to override it
		Init.init();

		String log4jConfigFileLocation = getServletConfig().getInitParameter("log4jConfigFileLocation");
		if (log4jConfigFileLocation == null) {
			log4jConfigFileLocation = "/WEB-INF/conf/log4j.properties";
		}
		PropertyConfigurator.configure(getServletContext().getRealPath("/") + log4jConfigFileLocation);
		log.info("Logger initialized.");
	}

}

