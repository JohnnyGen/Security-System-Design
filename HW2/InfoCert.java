package HW2_TEST;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class InfoCert {
    public static void main(String[] args) {
        // Assicurati che il percorso al keystore e le credenziali siano corretti
        String keystorePath = "C:\\Users\\gioge\\Desktop\\System Security\\HW2\\keystore.jks";
        String keystorePassword = "ciao123";
        String alias = "certificato";

        // Gestione delle risorse con try-with-resources per il keystore
        try (FileInputStream keystoreStream = new FileInputStream(keystorePath)) {

            // Carichiamo il keystore
            KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(keystoreStream, keystorePassword.toCharArray());

            // Otteniamo il certificato dal keystore
            Certificate Certificato = keystore.getCertificate(alias);

            // Verifica se è un certificato X509
            if (Certificato instanceof X509Certificate) {
                X509Certificate Certificato_X509 = (X509Certificate) Certificato;

                // Estrazione informazioni dal certificato
                System.out.println("\nOwner: " + Certificato_X509.getSubjectX500Principal());
                System.out.println("Issuer: " + Certificato_X509.getIssuerX500Principal());
                System.out.println("Serial Number: " + Certificato_X509.getSerialNumber());
                System.out.println("Valid from: " + Certificato_X509.getNotBefore() + "until: "+ Certificato_X509.getNotAfter());
                System.out.println("Signature algorithm: " + Certificato_X509.getSigAlgName());
            } else {
                System.out.println("ERRORE: Il certificato non è di tipo X.509");
            }

        } catch (Exception e) {
            // Gestione errori
            System.err.println("ERRORE:");
            e.printStackTrace();
        }
    }
}

