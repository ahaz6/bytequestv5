package com.bytequest;

import java.io.Serializable;

/*
 * LoginToken - das serialisierte "Login-Objekt".
 *
 * So ein Objekt wuerde in echten Apps z.B. in einem Cookie oder "Remember me"-
 * Feld transportiert und beim Anmelden wieder deserialisiert. Genau das ist die
 * Angriffsflaeche fuer Insecure Deserialization (OWASP A08).
 */
public class LoginToken implements Serializable {

    private static final long serialVersionUID = 1L;

    private String username;
    private String role;   // "user" oder (manipuliert) "admin"

    public LoginToken(String username, String role) {
        this.username = username;
        this.role = role;
    }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }
}
