package br.com.sistel.exemplo.filter;

import jcifs.CIFSContext;
import jcifs.config.PropertyConfiguration;
import jcifs.context.BaseContext;
import jcifs.ntlmssp.Type1Message;
import jcifs.ntlmssp.Type2Message;
import jcifs.ntlmssp.Type3Message;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb1.util.Base64;
//import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Properties;

@Configuration
public class NtlmAuthConfig {

    @Value("${ntlm.domain}")
    private String domain;

    @Value("${ntlm.domainController}")
    private String domainController;

    @Bean
    public FilterRegistrationBean<NtlmAuthFilter> ntlmFilter() {
        FilterRegistrationBean<NtlmAuthFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new NtlmAuthFilter(domain, domainController));
        registrationBean.addUrlPatterns("/*");
        return registrationBean;
    }
}

class NtlmAuthFilter extends OncePerRequestFilter {
    private static final Logger log = LoggerFactory.getLogger(NtlmAuthFilter.class);
    private static final String NTLM_AUTH_SESSION_KEY = "NTLM_AUTH";

    private final String domain;
    private final String domainController;
    private CIFSContext cifsContext;

    public NtlmAuthFilter(String domain, String domainController) {
        this.domain = domain;
        this.domainController = domainController;
        initializeCifsContext();
    }

    private void initializeCifsContext() {
        try {
            Properties props = new Properties();
            props.setProperty("jcifs.smb.client.domain", domain);
            props.setProperty("jcifs.netbios.wins", domainController);
            props.setProperty("jcifs.smb.client.soTimeout", "300000");
            props.setProperty("jcifs.smb.client.responseTimeout", "30000");
            props.setProperty("jcifs.smb.client.useExtendedSecurity", "false");

            this.cifsContext = new BaseContext(new PropertyConfiguration(props));

            log.info("NTLM Filter initialized with domain: {} and DC: {}", domain, domainController);
        } catch (Exception e) {
            log.error("Error initializing CIFS context", e);
            throw new RuntimeException("Failed to initialize NTLM filter", e);
        }
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        try {
            HttpSession session = request.getSession(false);
            NtlmPasswordAuthentication auth = getAuthenticationFromSession(session);

            if (auth != null) {
                log.debug("User already authenticated: {}", auth.getName());
                filterChain.doFilter(new NtlmHttpRequestWrapper(request, auth), response);
                return;
            }

            String authHeader = request.getHeader("Authorization");

            if (authHeader == null) {
                // Inicia a autenticação NTLM
                initiateNtlmAuthentication(response);
                return;
            }

            if (authHeader.startsWith("NTLM ")) {
                // Decodifica o token NTLM
                String token = authHeader.substring(5).trim();
                byte[] tokenBytes = java.util.Base64.getDecoder().decode(token);

                // Verifica o tipo de mensagem NTLM
                if (tokenBytes[8] == 1) {
                    // Tipo 1: Responde com um desafio (Tipo 2)
                    Type1Message type1Message = new Type1Message(tokenBytes);

                    // Cria uma mensagem do Tipo 2
                    Type2Message type2Message = new Type2Message(
                            cifsContext, // CIFSContext
                            type1Message.getFlags(), // Flags da mensagem Tipo 1
                            new byte[8], // Desafio (8 bytes aleatórios)
                            null // Nome do domínio (opcional)
                    );

                    // Codifica a mensagem Tipo 2 em Base64
                    String type2MessageBase64 = java.util.Base64.getEncoder().encodeToString(type2Message.toByteArray());

                    // Responde com a mensagem Tipo 2
                    response.setHeader("WWW-Authenticate", "NTLM " + type2MessageBase64);
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                } else if (tokenBytes[8] == 3) {
                    // Tipo 3: Extrai as credenciais do usuário
                    Type3Message type3Message = new Type3Message(tokenBytes);
                    String username = type3Message.getUser();
                    String domain = type3Message.getDomain();
                    log.debug("Extracted username: {} and domain: {}", username, domain);

                    // Cria a autenticação NTLM
                    auth = new NtlmPasswordAuthentication(cifsContext, domain + ";" + username);
                    validateCredentials(auth);

                    // Armazena a autenticação na sessão
                    request.getSession().setAttribute(NTLM_AUTH_SESSION_KEY, auth);
                    filterChain.doFilter(new NtlmHttpRequestWrapper(request, auth), response);
                    return;
                } else {
                    throw new IOException("Invalid NTLM message type");
                }
            }

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        } catch (Exception e) {
            log.error("Error during NTLM authentication", e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Authentication error");
        }
    }

    private NtlmPasswordAuthentication getAuthenticationFromSession(HttpSession session) {
        if (session != null) {
            Object auth = session.getAttribute(NTLM_AUTH_SESSION_KEY);
            if (auth instanceof NtlmPasswordAuthentication) {
                return (NtlmPasswordAuthentication) auth;
            }
        }
        return null;
    }

    private void initiateNtlmAuthentication(HttpServletResponse response) {
        response.setHeader("WWW-Authenticate", "NTLM");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    private NtlmPasswordAuthentication processNtlmAuthentication(String authHeader)
            throws IOException {
        try {
            // Extrair as informações do usuário do header NTLM
            String userInfo = extractUserInfo(authHeader);
            return new NtlmPasswordAuthentication(cifsContext, userInfo);

        } catch (Exception e) {
            log.error("Error processing NTLM message", e);
            throw new IOException("NTLM authentication failed", e);
        }
    }

    private String extractUserInfo(String authHeader) throws IOException {
        try {
            // Remove o prefixo "NTLM " do cabeçalho
            String token = authHeader.substring(5).trim();

            // Decodifica o token Base64
            byte[] tokenBytes = Base64.decode(token);

            // Verifica se é uma mensagem NTLM Type3 (contém as credenciais do usuário)
            if (tokenBytes[8] == 3) {
                Type3Message type3Message = new Type3Message(tokenBytes);
                String username = type3Message.getUser();
                String domain = type3Message.getDomain();
                log.debug("Extracted username: {} and domain: {}", username, domain);
                return domain + ";" + username; // Formato esperado pelo NtlmPasswordAuthentication
            } else {
                throw new IOException("Invalid NTLM message type");
            }
        } catch (Exception e) {
            log.error("Error extracting user info from NTLM token", e);
            throw new IOException("Failed to extract user info", e);
        }
    }

    private void validateCredentials(NtlmPasswordAuthentication auth) throws IOException {
        try {
            cifsContext.withCredentials(auth);
            log.info("User {} authenticated successfully", auth.getName());
        } catch (Exception e) {
            log.error("Failed to validate credentials", e);
            throw new IOException("Failed to validate credentials", e);
        }
    }
}