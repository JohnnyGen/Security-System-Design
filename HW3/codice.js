function main() {
    
    const percorso = 'certificates/localhost.crt';

    // Carica il file del certificato
    fetch(percorso)
        .then(response => {
            if (!response.ok) {
                throw new Error('ERRORE.');
            }
            return response.text();
        })
        .then(certificato => {
            document.getElementById('certInfo').textContent = certificato;
        })
        .catch(e => {
            document.getElementById('certInfo').textContent = 
                'Errore nel caricamento: ' + e.message;
        });
}
