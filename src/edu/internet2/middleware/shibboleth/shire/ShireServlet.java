package edu.internet2.middleware.shibboleth.shire;

import edu.internet2.middleware.shibboleth.common.*;

import java.io.*;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.text.*;
import javax.servlet.*;
import javax.servlet.http.*;
import org.doomdark.uuid.*;
import org.opensaml.*;

/**
 *  Implements a SAML POST profile consumer
 *
 * @author     Scott Cantor, Sridhar Muppidi
 * @created    June 10, 2002
 */
public class ShireServlet extends HttpServlet
{
    private String cookieName = null;
    private String sessionDir = null;
    private boolean sslOnly = true;
    private boolean checkAddress = true;
    private boolean verbose = false;
    private XMLOriginSiteMapper mapper = null;

    private static void HTMLFormat(PrintWriter pw, String buf)
    {
        for (int i = 0; i < buf.length(); i++)
        {
            if (buf.charAt(i) == '<')
                pw.write("&lt;");
            else if (buf.charAt(i) == '>')
                pw.write("&gt;");
            else if (buf.charAt(i) == '&')
                pw.write("&amp;");
            else
                pw.write(buf.charAt(i));
        }
    }

    /**
     *  Use the following servlet init parameters:<P>
     *
     *
     *  <DL>
     *    <DT> keystore-path <I>(required)</I> </DT>
     *    <DD> A pathname to the trusted CA roots to accept</DD>
     *    <DT> keystore-password <I>(required)</I> </DT>
     *    <DD> The root keystore password</DD>
     *    <DT> registry-alias <I>(optional)</I> </DT>
     *    <DD> An alias in the provided keystore for the cert that can verify
     *    the origin site registry signature</DD>
     *    <DT> registry-uri <I>(required)</I> </DT>
     *    <DD> The origin site registry URI to install</DD>
     *    <DT> cookie-name <I>(required)</I> </DT>
     *    <DD> Name of session cookie to set in browser</DD>
     *    <DT> ssl-only <I>(defaults to true)</I> </DT>
     *    <DD> If true, allow only SSL-protected POSTs and issue a secure cookie
     *    </DD>
     *    <DT> check-address <I>(defaults to true)</I> </DT>
     *    <DD> If true, check client's IP address against assertion</DD>
     *    <DT> session-dir <I>(defaults to /tmp)</I> </DT>
     *    <DD> Directory in which to place session files</DD>
     *    <DT> verbose <I>(defaults to false)</I> </DT>
     *    <DD> Verbosity of redirection response</DD>
     *  </DL>
     *
     *
     * @exception  ServletException  Raised if the servlet cannot be initialized
     */
    public void init()
        throws ServletException
    {
        ServletConfig conf = getServletConfig();

        cookieName = conf.getInitParameter("cookie-name");
        if (cookieName == null)
            throw new ServletException("ShireServlet.init() missing init parameter: cookie-name");

        sessionDir = conf.getInitParameter("session-dir");
        if (sessionDir == null)
            sessionDir = "/tmp";

        String temp = conf.getInitParameter("ssl-only");
        if (temp != null && (temp.equalsIgnoreCase("false") || temp.equals("0")))
            sslOnly = false;

        temp = conf.getInitParameter("check-address");
        if (temp != null && (temp.equalsIgnoreCase("false") || temp.equals("0")))
            checkAddress = false;

        temp = conf.getInitParameter("verbose");
        if (temp != null && (temp.equalsIgnoreCase("true") || temp.equals("1")))
            verbose = true;

        try
        {
            Key k = null;
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(conf.getServletContext().getResourceAsStream(conf.getInitParameter("keystore-path")),
                    conf.getInitParameter("keystore-password").toCharArray());
            if (conf.getInitParameter("keystore-alias") != null)
            {
                Certificate cert = ks.getCertificate(conf.getInitParameter("keystore-alias"));
                if (cert == null || (k = cert.getPublicKey()) == null)
                    throw new ServletException("ShireServlet.init() unable to find registry verification certificate/key");
            }
            mapper = new XMLOriginSiteMapper(conf.getInitParameter("registry-uri"), k, ks);
        }
        catch (org.apache.xml.security.exceptions.XMLSecurityException e)
        {
            throw new ServletException(e.getMessage());
        }
        catch (java.security.KeyStoreException e)
        {
            throw new ServletException("ShireServlet.init() unable to load Java keystore");
        }
        catch (java.security.NoSuchAlgorithmException e)
        {
            throw new ServletException("ShireServlet.init() unable to load Java keystore");
        }
        catch (java.security.cert.CertificateException e)
        {
            throw new ServletException("ShireServlet.init() unable to load Java keystore");
        }
        catch (FileNotFoundException e)
        {
            throw new ServletException("ShireServlet.init() unable to locate Java keystore");
        }
        catch (IOException e)
        {
            throw new ServletException("ShireServlet.init() unable to load Java keystore");
        }
        catch (org.xml.sax.SAXException e)
        {
            throw new ServletException("ShireServlet.init() unable to load origin site registry");
        }
    }

    /**
     *  Processes a sign-on submission<P>
     *
     *
     *
     * @param  request               HTTP request context
     * @param  response              HTTP response context
     * @exception  IOException       Thrown if an I/O error occurs
     * @exception  ServletException  Thrown if a servlet engine error occurs
     */
    public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws IOException, ServletException
    {
        // Output page opener.
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<HTML>");
        out.println("<HEAD>");
        out.println("<TITLE>Shibboleth Session Establisher</TITLE>");
        out.println("</HEAD>");
        out.println("<BODY>");
        out.println("<H3>Shibboleth Session Establisher</H3>");

        if (sslOnly && !request.isSecure())
        {
            out.println("<H4>There was a problem with this submission.</H4>");
            out.println("<P>Access to this site requires the use of SSL. To correct the problem, please re-enter the desired target URL into your browser and make sure it begins with 'https'.</P>");
            out.println("</BODY></HTML>");
            return;
        }

        String target = request.getParameter("TARGET");
        if (target == null || target.length() == 0)
        {
            out.println("<H4>There was a problem with this submission.</H4>");
            out.println("<P>The target location was unspecified. To correct the problem, please re-enter the desired target URL into your browser.</P>");
            out.println("</BODY></HTML>");
            return;
        }
        else if (verbose)
            out.println("<P><B>Target URL:</B>" + target + "</P>");

        String responseData = request.getParameter("SAMLResponse");
        if (responseData == null || responseData.length() == 0)
        {
            out.println("<H4>There was a problem with this submission.</H4>");
            out.println("<P>The assertion of your Shibboleth identity was missing. To correct the problem, please re-enter the desired target URL into your browser.</P>");
            out.println("</BODY></HTML>");
            return;
        }

        // Process the SAML response inside an exception handler.
        try
        {
            // Get a profile object using our specifics.
            String[] policies = {Constants.POLICY_CLUBSHIB};
            ShibPOSTProfile profile =
                ShibPOSTProfileFactory.getInstance(policies, mapper, HttpUtils.getRequestURL(request).toString(), 300);

            // Try and accept the response...
            SAMLResponse r = profile.accept(responseData.getBytes());

            // We've got a valid signed response we can trust (or the whole response was empty...)
            if (verbose)
            {
                ByteArrayOutputStream bytestr = new ByteArrayOutputStream();
                r.toStream(bytestr);
                out.println("<P><B>Parsed SAML Response:</B></P>");
                out.println("<P>");
                HTMLFormat(out, bytestr.toString(response.getCharacterEncoding()));
                out.println("</P>");
            }

            // Get the statement we need.
            SAMLAuthenticationStatement s = profile.getSSOStatement(r);
            if (s == null)
            {
                out.println("<H4>There was a problem with this submission.</H4>");
                out.println("<P>The assertion of your Shibboleth identity was missing or incompatible with the policies of this site. To correct the problem, please re-enter the desired target URL into your browser. If the problem persists, please contact the technical staff at your site.</P>");
                out.println("</BODY></HTML>");
                return;
            }

            if (checkAddress)
            {
                if (verbose)
                    out.println("<P><B>Client Address:</B>" + request.getRemoteAddr() + "</P>");
                if (s.getSubjectIP() == null || !s.getSubjectIP().equals(request.getRemoteAddr()))
                {
                    if (verbose && s.getSubjectIP() != null)
                        out.println("<P><B>Supplied Client Address:</B>" + s.getSubjectIP() + "</P>");
                    out.println("<H4>There was a problem with this submission.</H4>");
                    out.println("<P>The IP address provided by your origin site was either missing or did not match your current address. To correct this problem, you may need to bypass a local proxy server and/or contact your origin site technical staff.</P>");
                    out.println("</BODY></HTML>");
                }
            }

            // All we really need is here...
            String handle = s.getSubject().getName();
            String domain = s.getSubject().getNameQualifier();
            SAMLAuthorityBinding[] bindings = s.getBindings();

            if (verbose)
            {
                out.println("<P><B>Shibboleth Origin Site:</B>" + domain + "</P>");
                out.println("<P><B>Shibboleth Handle:</B>" + handle + "</P>");
                if (bindings != null)
                    out.println("<P><B>Shibboleth AA URL:</B>" + bindings[0].getLocation() + "</P>");
            }

            // Generate a random session file.
            String filename = UUIDGenerator.getInstance().generateRandomBasedUUID().toString().replace('-', '_');
            String pathname = null;
            if (sessionDir.endsWith(File.separator))
                pathname = sessionDir + filename;
            else
                pathname = sessionDir + File.separatorChar + filename;
            PrintWriter fout = new PrintWriter(new FileWriter(pathname));

            if (verbose)
                out.println("<P><B>Session Pathname:</B>" + pathname + "</P>");

            fout.println("Handle=" + handle);
            fout.println("Domain=" + domain);
            fout.println("PBinding0=" + bindings[0].getBinding());
            fout.println("LBinding0=" + bindings[0].getLocation());
            fout.println("EOF");
            fout.close();

            out.println("<P>Redirecting you to your target...</P>");
            out.println("<P>Allow 10-15 seconds, then click <A HREF='" + target + "'>here</A> if you do not get redirected.</P>");
            out.println("</BODY></HTML>");

            // Set the session cookie.
            Cookie cookie = new Cookie(cookieName, filename);
            cookie.setPath("/");
            response.addCookie(cookie);

            // Redirect back to the requested resource.
            response.sendRedirect(target);
        }
        catch (SAMLException e)
        {
            out.println("<H4>There was a problem with this submission.</H4>");
            out.println("<P>The system detected the following error while processing your submission:</P>");
            out.println("<BLOCKQUOTE>" + e.toString() + "</BLOCKQUOTE>");
            out.println("<P>Please contact this site's administrator to resolve the problem.</P>");
            out.println("</BODY></HTML>");
        }
    }
}

