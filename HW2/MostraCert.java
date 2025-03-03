package HW2_TEST;
import java.io.FileInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

public class MostraCert {

    public static void main(String[] args) {

        // Percorso al file .crt
        String percorsoCert = "C:\\Users\\gioge\\Desktop\\System Security\\HW1\\certificate.crt";

        // Gestione risorse con try-with-resources per il flusso di input del certificato
        try (FileInputStream Certificato = new FileInputStream(percorsoCert)) {

            // Crea un CertificateFactory per il tipo X.509
            CertificateFactory CFact = CertificateFactory.getInstance("X.509");

            // Legge il file del certificato
            Certificate Cert = CFact.generateCertificate(Certificato);

            // Mostra le informazioni del certificato
            System.out.println("Certificato caricato. ");
            System.out.println(Cert.toString());

        } catch (Exception e) {
            // Gestione degli errori
            System.err.println("ERRORE: certificato non caricato correttamente.");
            e.printStackTrace();
        }
    }
}
