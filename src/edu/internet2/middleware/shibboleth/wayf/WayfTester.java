package edu.internet2.middleware.shibboleth.wayf;

import java.io.IOException;
import java.net.URLEncoder;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/*
 * This class is simply redirects to hardcoded URL for the WAYF.  Created for testing during 
 * development.  Should probably delete later and replace with a proper testing environment.
 */

public class WayfTester extends HttpServlet {

	private String acceptanceURL = "http://localhost/wayf/SHIRE";
	private String targetURL = "http://localhost/wayf/success.html";

	public void doGet(HttpServletRequest req, HttpServletResponse res) {

		
		try {
			res.sendRedirect(
				"WAYF" + "?target=" + URLEncoder.encode(targetURL) + "&shire=" + URLEncoder.encode(acceptanceURL));
		} catch (IOException ioe) {
			System.out.println("WAYF Tester Error");
		}

	}

}
