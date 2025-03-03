Client Secret: kf7mC1NafuEMQMDyFklZFAYqhfW8ZYcC


NON MODIFICARE APP.PY

REQUIREMENTS

NomeComponente       Tipo               Versione
Apache               http server        2.4.62  
Vault                gestione segreti   1.18.1
Flask                framework web      3.1.0	(2.2.5)
Keycloak             autenticazione     26.1.0	(26.0.5)

CMD

vault read auth/oidc/role/default
vault read auth/oidc/config
vault write auth/oidc/role/default verbose_oidc_logging=true

Far partire vault, docker e app.py per usare KeyCloak

vault server -config="C:\Vault\vault-config.hcl"

docker run -p 8081:8080 -v C:/Users/forma/Desktop/SSD/HW6/db:/opt/keycloak/data -e KC_DB=dev-file -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:26.1.0 start-dev

1) Creare un nuovo Realm (WebApp) e aggiungere cose, quali:
2) Creare un client
3) Creare una risorsa: clients->authorization->resources
4) Crea un ruolo (admin): clients->roles
4) Creare una Policy: clients->authorization->policies (tipo role: Admin Policy)
5) Creare un permesso: Clients->Authorization->Permissions (non sono sicuro ma ho messo resource-base)



