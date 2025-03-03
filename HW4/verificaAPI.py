import requests

VAULT_ADDR = "https://127.0.0.1:8200"
VAULT_VERIFY = False  # Disabilita la verifica del certificato

url = f"{VAULT_ADDR}/v1/sys/seal-status"
response = requests.get(url, verify=VAULT_VERIFY)

if response.status_code == 200:
    print("Vault is reachable")
else:
    print(f"Failed to reach Vault. Status code: {response.status_code}")
