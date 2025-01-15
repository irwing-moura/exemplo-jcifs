package br.com.sistel.exemplo.controller;


import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;


@RestController
@RequestMapping("/api/usuario")
public class UsuarioController {

    @RequestMapping(value = "/logado", method = RequestMethod.GET)
    public ResponseEntity<?> consultarUsuarioLogado(HttpSession session) {

        return ResponseEntity.ok("Usuário Logado: "+session.getAttribute("USUARIO_LOGADO"));
    }


}
