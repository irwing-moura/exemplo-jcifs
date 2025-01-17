package br.com.sistel.exemplo.filter;

import jcifs.smb.NtlmPasswordAuthentication;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.security.Principal;

public class NtlmHttpRequestWrapper extends HttpServletRequestWrapper {
    private final NtlmPasswordAuthentication ntlmAuth;

    public NtlmHttpRequestWrapper(HttpServletRequest request,
                                  NtlmPasswordAuthentication ntlmAuth) {
        super(request);
        this.ntlmAuth = ntlmAuth;
    }

    @Override
    public String getRemoteUser() {
        return ntlmAuth != null ? ntlmAuth.getName() : null;
    }

    @Override
    public Principal getUserPrincipal() {
        return ntlmAuth;
    }

    @Override
    public boolean isUserInRole(String role) {
        return false; // Implemente a lógica de roles se necessário
    }
}