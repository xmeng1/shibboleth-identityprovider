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

package edu.internet2.middleware.shibboleth.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.util.Properties;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.xml.serialize.OutputFormat;
import org.apache.xml.serialize.XMLSerializer;
import org.opensaml.SAMLException;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import edu.internet2.middleware.shibboleth.aa.AAAttribute;
import edu.internet2.middleware.shibboleth.aa.AAAttributeSet;
import edu.internet2.middleware.shibboleth.aa.AAAttributeSet.ShibAttributeIterator;
import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver;
import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolverException;
import edu.internet2.middleware.shibboleth.common.AuthNPrincipal;
import gnu.getopt.Getopt;
import gnu.getopt.LongOpt;

/**
 * Utility for testing an Attribute Resolver configuration.
 * 
 * @author Walter Hoehn
 */

public class ResolverTest {

	private static Logger log = Logger.getLogger(ResolverTest.class.getName());
	private static boolean debug = false;
	private static String file = null;
	private static String requester = null;
	private static String user = null;

	public static void main(String[] args) {

		LongOpt[] longopts =
			{
				new LongOpt("help", LongOpt.NO_ARGUMENT, null, 'h'),
				new LongOpt("file", LongOpt.REQUIRED_ARGUMENT, null, 'f'),
				new LongOpt("user", LongOpt.REQUIRED_ARGUMENT, null, 'u'),
				new LongOpt("requester", LongOpt.REQUIRED_ARGUMENT, null, 'r'),
				new LongOpt("debug", LongOpt.NO_ARGUMENT, null, 'd')};

		Getopt getOpt = new Getopt("ResolverTest", args, ":hdf:u:r:", longopts);
		getOpt.setOpterr(false);

		for (int c;((c = getOpt.getopt()) != -1);) {
			switch (c) {

				case 'h' :
					printUsage(System.out);
					System.exit(0);
					break;

				case 'd' :
					debug = true;
					break;

				case 'f' :
					file = getOpt.getOptarg();
					break;

				case 'u' :
					user = getOpt.getOptarg();
					break;

				case 'r' :
					requester = getOpt.getOptarg();
					break;

				case ':' :
					System.out.println("You need an argument for option " + (char) getOpt.getOptopt());
					System.exit(1);

				case '?' :
					System.out.println("The option '" + (char) getOpt.getOptopt() + "' is not valid");
					System.exit(1);
			}
		}

		configureLogging(debug);
		checkRequired();

		Properties configuration = new Properties();
		configuration.setProperty(
			"edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver.ResolverConfig",
			file);
			
		try {
			AttributeResolver resolver = new AttributeResolver(configuration);
			String[] attributes = resolver.listRegisteredAttributeDefinitionPlugIns();

			AAAttributeSet attributeSet = new AAAttributeSet();
			for (int i = 0; i < attributes.length; i++) {
				attributeSet.add(new AAAttribute(attributes[i]));
			}

			resolver.resolveAttributes(new AuthNPrincipal(user), requester, attributeSet);

			System.out.println(
				"Received the following back from the Attribute Resolver:" + System.getProperty("line.separator"));
			
			for (ShibAttributeIterator iterator = attributeSet.shibAttributeIterator(); iterator.hasNext();) {
				AAAttribute attribute = iterator.nextShibAttribute();
				Node node = attribute.toDOM();
				ByteArrayOutputStream xml = new ByteArrayOutputStream();
				if (!(node instanceof Element)) {
					throw new IOException("Received bad Element data from SAML library.");
				}
				OutputFormat format = new OutputFormat();
				format.setIndenting(true);
				format.setIndent(4);
				new XMLSerializer(xml, format).serialize((Element) node);
				System.out.println(xml.toString() + System.getProperty("line.separator"));
			}
		} catch (AttributeResolverException e) {
			System.err.println("Error initializing the Attribute Resolver: " + e.getMessage());
		} catch (SAMLException e) {
			System.err.println("Error creating SAML attribute: " + e.getMessage());
		} catch (IOException e) {
			System.err.println("Error serializing output from Resolver: " + e.getMessage());
		}
	}

	private static void checkRequired() {
		if (file == null || user == null) {
			System.err.println("Missing required parameter(s).");
			try {
				Thread.sleep(100); //silliness to get error to print first
			} catch (InterruptedException e) {
				//doesn't matter
			}
			printUsage(System.out);
			System.exit(1);
		}
	}

	private static void configureLogging(boolean debugOn) {

		BasicConfigurator.configure();
		if (debug) {
			Logger.getRootLogger().setLevel(Level.DEBUG);
		} else {
			Logger.getRootLogger().setLevel(Level.INFO);
			Logger.getLogger("edu.internet2.middleware.shibboleth.aa.attrresolv").setLevel(Level.WARN);
		}
		Logger.getLogger("org.apache.xml.security").setLevel(Level.OFF);
	}

	private static void printUsage(PrintStream out) {

		out.println("Usage: resolvertest [options]..." + System.getProperty("line.separator"));
		out.println("Tests an AA Attribute Resolver configuration." + System.getProperty("line.separator"));

		out.println("-d, --debug                   run in debug mode");
		out.println("-h, --help                    print usage information");
		out.println("-f, --file=FILEURL            the URL of the resolver configuration");
		out.println("                                file (resolver.xml)");
		out.println("-u, --user=USER               the user for which attributes should");
		out.println("                                be resolved");
		out.println("-r, --requester=REQUESTER     the name of the requester (SHAR),");
		out.println("                                emulates unauthenticated requester if");
		out.println("                                not specified" + System.getProperty("line.separator"));

	}
}
