package HW2_TEST;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

public class ValidaCert {

    public static void main(String[] args) {
        // Percorso al keystore e password
        String Percorso_keystore = "C:\\Users\\gioge\\Desktop\\System Security\\HW2\\keystore.jks";
        String keystorePassword = "ciao123";
        String alias = "certificato";

        // Gestione risorse con try-with-resources per il keystore
        try (FileInputStream keystoreStream = new FileInputStream(Percorso_keystore)) {

            // Caricamento del keystore
            KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(keystoreStream, keystorePassword.toCharArray());

            // Ottenimento del certificato dal keystore usando l'alias
            Certificate Certificato = keystore.getCertificate(alias);

            if (Certificato instanceof X509Certificate) {
                X509Certificate Cert_X509 = (X509Certificate) Certificato;

                // Validazione della data di validità del certificato
                try {
                    Cert_X509.checkValidity();
                    System.out.println("\nCertificato valido.");
                } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                    System.out.println("Certificato non valido: " + e.getMessage());
                }

                // Controllo sull'algoritmo di firma
                String alg_firma = Cert_X509.getSigAlgName();
                if (alg_firma.equalsIgnoreCase("SHA256withRSA") || alg_firma.equalsIgnoreCase("SHA512withRSA")) {
                    System.out.println("Algoritmo sicuro. Algoritmo utilizzato: " + alg_firma);
                } else {
                    System.out.println("Algoritmo non sicuro: " + alg_firma);
                }
            } else {
                System.out.println("Il certificato non è X.509.");
            }

        } catch (Exception e) {
            // Gestione degli errori 
            System.err.println("ERRORE.");
            e.printStackTrace();
        }
    }
}
