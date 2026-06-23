package com.bytequest;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;

/*
 * LoginController - der EINZIGE Controller der App.
 *
 *   GET  /                -> Login-Seite
 *   POST /login/unsecure  -> UNSICHERE KONTROLLE  (Insecure Deserialization)
 *   POST /login/secure    -> SICHERE KONTROLLE    (Whitelist + Validierung)
 *   GET  /reset           -> alles zuruecksetzen
 *
 * Beide Login-Pfade bekommen denselben serialisierten Base64-Token. Der einzige
 * Unterschied ist, WIE er deserialisiert wird.
 */
@Controller
public class LoginController {

    @GetMapping("/")
    public String index(Model model) {
        // Beispiel-Tokens zum Ausprobieren (frisch serialisiert).
        model.addAttribute("tokenUser", serialize(new LoginToken("alex", "user")));
        model.addAttribute("tokenAdmin", serialize(new LoginToken("alex", "admin")));
        model.addAttribute("tokenRce", serialize(new ExploitGadget("cat /etc/passwd")));
        return "login";
    }

    /*
     * =====================================================================
     *  UNSICHERE KONTROLLE
     * =====================================================================
     * readObject() OHNE jede Pruefung. Je nachdem, was im Token steckt, geht es
     * unterschiedlich weiter:
     *   - LoginToken(role=admin) -> Admin-Bereich (Privilege Escalation)
     *   - ExploitGadget          -> readObject() feuert -> (simulierte) RCE
     */
    @PostMapping("/login/unsecure")
    public String loginUnsecure(@RequestParam("token") String token, Model model) {
        model.addAttribute("mode", "UNSICHERE KONTROLLE");
        List<String> out = new ArrayList<>();

        byte[] data;
        try {
            data = Base64.getDecoder().decode(token.trim());
        } catch (IllegalArgumentException e) {
            model.addAttribute("heading", "Fehler");
            model.addAttribute("lines", List.of("Ungueltiges Base64-Token."));
            return "result";
        }

        ExploitGadget.OUTPUT.clear();
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            // *** DIE VERWUNDBARE ZEILE *** - baut JEDE Klasse blind auf.
            Object obj = ois.readObject();

            // Falls ein Gadget gefeuert hat: dessen (simulierte) Ausgabe einsammeln.
            out.addAll(ExploitGadget.OUTPUT);
            ExploitGadget.OUTPUT.clear();

            if (obj instanceof LoginToken t) {
                if ("admin".equalsIgnoreCase(t.getRole())) {
                    model.addAttribute("heading", "Admin-Bereich betreten");
                    out.add("Token wurde 1:1 uebernommen - keine Pruefung.");
                    out.add("Benutzer: " + t.getUsername());
                    out.add("Rolle: " + t.getRole() + "  <-- Privilege Escalation!");
                } else {
                    model.addAttribute("heading", "Eingeloggt");
                    out.add("Benutzer: " + t.getUsername());
                    out.add("Rolle: " + t.getRole());
                }
            } else {
                model.addAttribute("heading", "Remote Code Execution (simuliert)");
                out.add("Es war gar kein Login-Token, sondern: " + obj.getClass().getName());
                out.add("readObject() lief bereits - der Schaden ist passiert.");
            }
        } catch (Exception e) {
            out.addAll(ExploitGadget.OUTPUT);
            ExploitGadget.OUTPUT.clear();
            model.addAttribute("heading", "Fehler beim Deserialisieren");
            out.add(e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        model.addAttribute("lines", out);
        return "result";
    }

    /*
     * =====================================================================
     *  SICHERE KONTROLLE
     * =====================================================================
     * Whitelist-Stream laesst nur LoginToken zu (ein Gadget wird abgelehnt,
     * BEVOR readObject() laeuft). Danach wird die Rolle validiert. Ergebnis:
     * Login erfolgreich.
     */
    @PostMapping("/login/secure")
    public String loginSecure(@RequestParam("token") String token, Model model) {
        model.addAttribute("mode", "SICHERE KONTROLLE");
        List<String> out = new ArrayList<>();

        byte[] data;
        try {
            data = Base64.getDecoder().decode(token.trim());
        } catch (IllegalArgumentException e) {
            model.addAttribute("heading", "Fehler");
            model.addAttribute("lines", List.of("Ungueltiges Base64-Token."));
            return "result";
        }

        ExploitGadget.OUTPUT.clear();
        try (ObjectInputStream ois = new WhitelistInputStream(new ByteArrayInputStream(data))) {
            Object obj = ois.readObject();

            if (!(obj instanceof LoginToken t)) {
                model.addAttribute("heading", "Abgelehnt");
                model.addAttribute("lines", List.of("Kein gueltiger Login-Token."));
                return "result";
            }

            // Validierung: nur Rolle "user" erlaubt - Eskalation wird verhindert.
            if (!"user".equalsIgnoreCase(t.getRole())) {
                out.add("Rolle '" + t.getRole() + "' nicht erlaubt -> auf 'user' zurueckgesetzt.");
                t.setRole("user");
            }
            model.addAttribute("heading", "Login erfolgreich");
            out.add("Willkommen, " + t.getUsername() + " (Rolle: " + t.getRole() + ").");
        } catch (InvalidClassException e) {
            ExploitGadget.OUTPUT.clear();
            model.addAttribute("heading", "Angriff blockiert");
            out.add("Nicht erlaubte Klasse abgelehnt: " + e.getMessage());
            out.add("Das Gadget wurde NICHT deserialisiert - keine Code-Ausfuehrung.");
        } catch (Exception e) {
            model.addAttribute("heading", "Fehler");
            out.add(e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        model.addAttribute("lines", out);
        return "result";
    }

    @GetMapping("/reset")
    public String reset() {
        ExploitGadget.OUTPUT.clear();
        return "redirect:/";
    }

    /* ------------------------------------------------------------------ */

    private String serialize(Serializable obj) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
                oos.writeObject(obj);
            }
            return Base64.getEncoder().encodeToString(bos.toByteArray());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /*
     * Der FIX: ein ObjectInputStream, der nur erlaubte Klassen aufbaut.
     */
    private static final class WhitelistInputStream extends ObjectInputStream {
        private static final Set<String> ALLOWED = Set.of(
                LoginToken.class.getName(),
                "java.lang.String"
        );

        WhitelistInputStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc)
                throws IOException, ClassNotFoundException {
            if (!ALLOWED.contains(desc.getName())) {
                throw new InvalidClassException(desc.getName());
            }
            return super.resolveClass(desc);
        }
    }

    /*
     * Eigene Exception fuer eine klare Meldung beim Blockieren.
     */
    private static final class InvalidClassException extends IOException {
        InvalidClassException(String className) {
            super(className);
        }
    }
}
