import hashlib
import requests

def check_password_pwned(password):
    """Verifica si la contraseña ha sido filtrada en bases de datos públicas usando la API de Have I Been Pwned."""
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1_hash[:5]  # Solo enviamos los primeros 5 caracteres del hash
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    
    response = requests.get(url)
    
    if response.status_code == 200:
        hashes = response.text.splitlines()
        leaked_hashes = {line.split(":")[0]: int(line.split(":")[1]) for line in hashes}
        
        if sha1_hash[5:] in leaked_hashes:
            return f"⚠️ La contraseña ha sido encontrada en {leaked_hashes[sha1_hash[5:]]} filtraciones. ¡Considera cambiarla!"
        else:
            return "✅ La contraseña **no** ha sido encontrada en filtraciones conocidas."
    else:
        return "❌ Error al consultar la API de Have I Been Pwned."