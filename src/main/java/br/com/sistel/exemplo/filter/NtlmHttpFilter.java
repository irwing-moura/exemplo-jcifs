package br.com.sistel.exemplo.filter;

import jcifs.Config;
import jcifs.UniAddress;
import jcifs.http.NtlmSsp;
import jcifs.smb.NtlmChallenge;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbSession;
import jcifs.util.Base64;
import jcifs.util.LogStream;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Enumeration;

/**
 * This servlet Filter can be used to negotiate password hashes with
 * MSIE clients using NTLM SSP. This is similar to <tt>Authentication:
 * BASIC</tt> but weakly encrypted and without requiring the user to re-supply
 * authentication credentials.
 * <p>
 * Read <a href="../../../ntlmhttpauth.html">jCIFS NTLM HTTP Authentication and the Network Explorer Servlet</a> for complete details.
 */

public class NtlmHttpFilter implements Filter {


    private static final String USUARIO_LOCAL = "usuario.acesso.local";
    private static LogStream log = LogStream.getInstance();

    private String defaultDomain;
    private String domainController;
    private boolean loadBalance;
    private boolean enableBasic;
    private boolean insecureBasic;
    private String realm;
    private String usuarioAcessoLocal;


    public void init( FilterConfig filterConfig ) throws ServletException {
        String name;
        int level;

        /* Set jcifs properties we know we want; soTimeout and cachePolicy to 30min.
         */
        Config.setProperty( "jcifs.smb.client.soTimeout", "1800000" );
        Config.setProperty( "jcifs.netbios.cachePolicy", "1200" );
        /* The Filter can only work with NTLMv1 as it uses a man-in-the-middle
         * techinque that NTLMv2 specifically thwarts. A real NTLM Filter would
         * need to do a NETLOGON RPC that JCIFS will likely never implement
         * because it requires a lot of extra crypto not used by CIFS.
         */
        Config.setProperty( "jcifs.smb.lmCompatibility", "0" );
        Config.setProperty( "jcifs.smb.client.useExtendedSecurity", "false" );

        Enumeration e = filterConfig.getInitParameterNames();
        while( e.hasMoreElements() ) {
            name = (String)e.nextElement();
            if( name.startsWith( "jcifs." )) {
                Config.setProperty( name, filterConfig.getInitParameter( name ));
            }
        }
        usuarioAcessoLocal = Config.getProperty("jcifs.usuario.acesso.local");
        defaultDomain = Config.getProperty("jcifs.smb.client.domain");
        domainController = Config.getProperty( "jcifs.http.domainController" );
        if( domainController == null ) {
            domainController = defaultDomain;
            loadBalance = Config.getBoolean( "jcifs.http.loadBalance", true );
        }
        enableBasic = Boolean.valueOf(
                Config.getProperty("jcifs.http.enableBasic"));
        insecureBasic = Boolean.valueOf(
                Config.getProperty("jcifs.http.insecureBasic"));
        realm = Config.getProperty("jcifs.http.basicRealm");
        if (realm == null) realm = "jCIFS";

        if(( level = Config.getInt( "jcifs.util.loglevel", -1 )) != -1 ) {
            LogStream.setLevel( level );
        }
        if( log.level > 2 ) {
            try {
                Config.store( log, "JCIFS PROPERTIES" );
            } catch( IOException ioe ) {
            }
        }
    }

    public void destroy() {
    }

    /**
     * This method simply calls <tt>negotiate( req, resp, false )</tt>
     * and then <tt>chain.doFilter</tt>. You can override and call
     * negotiate manually to achive a variety of different behavior.
     */
    public void doFilter( ServletRequest request,
                          ServletResponse response,
                          FilterChain chain ) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest)request;
        HttpServletResponse resp = (HttpServletResponse)response;
        NtlmPasswordAuthentication ntlm;

        if(req.getRequestURI().contains("swagger")) {
            req.getSession().setAttribute(USUARIO_LOCAL, usuarioAcessoLocal);
            chain.doFilter(req, response);
            return;
        }

        if(usuarioAcessoLocal!=null && usuarioAcessoLocal.length()>0){
            req.getSession().setAttribute(USUARIO_LOCAL, usuarioAcessoLocal);
            chain.doFilter( req, response );
            return;
        }

        if ((ntlm = negotiate( req, resp, false )) == null) {
            return;
        }

        chain.doFilter( new NtlmHttpServletRequest( req, ntlm ), response );
    }

    /**
     * Negotiate password hashes with MSIE clients using NTLM SSP
     * @param req The servlet request
     * @param resp The servlet response
     * @param skipAuthentication If true the negotiation is only done if it is
     * initiated by the client (MSIE post requests after successful NTLM SSP
     * authentication). If false and the user has not been authenticated yet
     * the client will be forced to send an authentication (server sends
     * HttpServletResponse.SC_UNAUTHORIZED).
     * @return True if the negotiation is complete, otherwise false
     */
    protected NtlmPasswordAuthentication negotiate( HttpServletRequest req,
                                                    HttpServletResponse resp,
                                                    boolean skipAuthentication ) throws IOException, ServletException {
        UniAddress dc;
        String msg;
        NtlmPasswordAuthentication ntlm = null;
        msg = req.getHeader( "Authorization" );
        boolean offerBasic = enableBasic && (insecureBasic || req.isSecure());

        if( msg != null && (msg.startsWith( "NTLM " ) ||
                (offerBasic && msg.startsWith("Basic ")))) {
            if (msg.startsWith("NTLM ")) {
                HttpSession ssn = req.getSession();
                byte[] challenge;

                if( loadBalance ) {
                    NtlmChallenge chal = (NtlmChallenge)ssn.getAttribute( "NtlmHttpChal" );
                    if( chal == null ) {
                        chal = SmbSession.getChallengeForDomain();
                        ssn.setAttribute( "NtlmHttpChal", chal );
                    }
                    dc = chal.dc;
                    challenge = chal.challenge;
                } else {
                    dc = UniAddress.getByName( domainController, true );
                    challenge = SmbSession.getChallenge( dc );
                }

                if(( ntlm = NtlmSsp.authenticate( req, resp, challenge )) == null ) {

                    resp.setStatus( HttpServletResponse.SC_UNAUTHORIZED );
                    resp.setContentType("text/plain");
                    resp.getWriter().write("Acesso Não Autorizado");
                    resp.getWriter().flush();
                    resp.flushBuffer();
                    return null;
                }
                /* negotiation complete, remove the challenge object */
                ssn.removeAttribute( "NtlmHttpChal" );
            } else {
                String auth = new String(Base64.decode(msg.substring(6)),
                        "US-ASCII");
                int index = auth.indexOf(':');
                String user = (index != -1) ? auth.substring(0, index) : auth;
                String password = (index != -1) ? auth.substring(index + 1) :
                        "";
                index = user.indexOf('\\');
                if (index == -1) index = user.indexOf('/');
                String domain = (index != -1) ? user.substring(0, index) :
                        defaultDomain;
                user = (index != -1) ? user.substring(index + 1) : user;
                ntlm = new NtlmPasswordAuthentication(domain, user, password);
                dc = UniAddress.getByName( domainController, true );
            }

            try {

                SmbSession.logon( dc, ntlm );

                if( log.level > 2 ) {
                    log.println( "NtlmHttpFilter: " + ntlm +
                            " successfully authenticated against " + dc );
                }
            } catch( Exception sae ) {
                resp.setStatus( HttpServletResponse.SC_UNAUTHORIZED );
                resp.setContentType("text/plain");
                resp.getWriter().write("Acesso Não Autorizado");
                resp.getWriter().flush();
                resp.flushBuffer();
                return null;
            }
            req.getSession().setAttribute( "NtlmHttpAuth", ntlm );
        } else {
            if (!skipAuthentication) {
                HttpSession ssn = req.getSession(false);
                if (ssn == null || (ntlm = (NtlmPasswordAuthentication)
                        ssn.getAttribute("NtlmHttpAuth")) == null) {
                    resp.setHeader( "WWW-Authenticate", "NTLM" );
                    if (offerBasic) {
                        resp.addHeader( "WWW-Authenticate", "Basic realm=\"" +
                                realm + "\"");
                    }
                    resp.setStatus( HttpServletResponse.SC_UNAUTHORIZED );
                    resp.setContentType("text/plain");
                    resp.getWriter().write("Acesso Não Autorizado");
                    resp.getWriter().flush();
                    resp.flushBuffer();
                    return null;
                }
            }
        }

        return ntlm;
    }

}

