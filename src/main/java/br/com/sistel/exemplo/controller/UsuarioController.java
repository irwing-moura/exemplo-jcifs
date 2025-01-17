package br.com.sistel.exemplo.controller;


import jcifs.smb.NtlmPasswordAuthentication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;


@RestController
@RequestMapping("/api/usuario")
public class UsuarioController {

    @RequestMapping(value = "/logado", method = RequestMethod.GET)
    public ResponseEntity<?> consultarUsuarioLogado(HttpSession session, HttpServletRequest request) {

        NtlmPasswordAuthentication auth = (NtlmPasswordAuthentication)
                request.getSession().getAttribute("NTLM_AUTH");
        if (auth != null) {
            return ResponseEntity.ok("Usuário: " + auth.getName());
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Usuário não autenticado");
    }
}