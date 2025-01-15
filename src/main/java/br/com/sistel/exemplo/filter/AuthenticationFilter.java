package br.com.sistel.exemplo.filter;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@Order(2)
public class AuthenticationFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        //Obtem o login do usuário capturado no NtlmHttpFilter
        String loginUsuario = "";

        if (request.getRemoteUser() != null) {

            if(request.getRemoteUser().contains("NTAS")){
                loginUsuario = request.getRemoteUser().substring(5, request.getRemoteUser().length()).toLowerCase();
            }else{
                loginUsuario = request.getRemoteUser();
            }

        }

        request.getSession().setAttribute("USUARIO_LOGADO", loginUsuario);

        System.out.println(String.format("Usuário Logado: %s", loginUsuario));

        //Deixo prosseguir a requisição
        filterChain.doFilter(request, response);


    }


    @Override
    public void destroy() {

    }
}

