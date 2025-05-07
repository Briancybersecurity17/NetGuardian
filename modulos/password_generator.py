import hashlib
import random
import string
import bcrypt

def generate_password(length=16, use_special_chars=True):
    """Genera una contraseña segura que siempre inicia con una letra mayúscula."""
    if length < 8:
        raise ValueError("La longitud mínima recomendada es 8 caracteres para seguridad.")
    
    characters = string.ascii_letters + string.digits
    if use_special_chars:
        characters += string.punctuation  # Agrega símbolos si el usuario lo permite
    
    # Garantiza que la primera letra sea mayúscula
    first_char = random.choice(string.ascii_uppercase)
    remaining_chars = ''.join(random.choice(characters) for _ in range(length - 1))
    
    return first_char + remaining_chars

def hash_password(password, algorithm="sha256"):
    """Genera el hash de la contraseña usando SHA-256, SHA-512 o bcrypt."""
    if algorithm == "sha256":
        return hashlib.sha256(password.encode()).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(password.encode()).hexdigest()
    elif algorithm == "bcrypt":
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode(), salt).decode()
    else:
        raise ValueError("Algoritmo no soportado. Usa 'sha256', 'sha512' o 'bcrypt'.")

