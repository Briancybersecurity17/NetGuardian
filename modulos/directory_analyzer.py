import os
import json
from PIL import Image
from PyPDF2 import PdfReader

def extract_image_metadata(file_path):
    try:
        image = Image.open(file_path)
        exif_data = image._getexif()
        return exif_data
    except Exception as e:
        return None

def extract_pdf_metadata(file_path):
    try:
        reader = PdfReader(file_path)
        metadata = reader.metadata  # Devuelve un diccionario con los metadatos
        return metadata
    except Exception as e:
        return None

def is_ecv_data_normal(value):
    """
    Intenta interpretar el contenido de '/ecv-data' y
    verifica que contenga claves esperadas (por ejemplo, 'style' y 'header').
    Si se cumple, se considera normal.
    """
    try:
        data = json.loads(value)
        if isinstance(data, dict) and "style" in data and "header" in data:
            return True
    except Exception:
        pass
    return False

def is_image_metadata_suspicious(metadata):
    """
    Revisa la metadata EXIF de una imagen y devuelve una lista de entradas sospechosas.
    Se espera que estén presentes campos comunes (271, 272, 306, 36867, 36868) y
    además se detecta inyección de código mediante patrones en los valores.
    """
    if not metadata:
        return []  # La ausencia puede considerarse normal
    
    # Definición básica de claves comunes (EXIF estándar)
    expected_keys = {271, 272, 306, 36867, 36868}
    # Opcional: podrías incluir aquí una whitelist de claves adicionales si lo deseas.
    suspicious_items = []
    
    for key, value in metadata.items():
        if isinstance(value, str):
            text = value.lower()
            # Detecta inyección de código
            if "<script" in text or "javascript:" in text:
                suspicious_items.append((key, value))
        # Si la clave no se encuentra en el conjunto esperado, podrías querer investigar;
        # sin embargo, debido a la gran variedad de marcas de cámara, puede resultar en falsos positivos.
        if key not in expected_keys:
            # Aquí se podría ampliar la validación; por defecto, no marcamos automáticamente.
            pass
    return suspicious_items

def is_pdf_metadata_suspicious(metadata):
    """
    Revisa la metadata de un PDF y devuelve una lista de entradas sospechosas.
    Se consideran sospechosos aquellos campos que no estén en el conjunto de claves comunes
    o que contengan fragmentos de código inyectado.
    Además, para campos conocidos en whitelist (por ejemplo, '/ecv-data'), solo se alerta si
    el contenido no coincide con el formato esperado.
    
    Este ajuste ignora el campo '/Trapped' si su valor es '/False'.
    También ignora campos adicionales si el valor está vacío.
    """
    if not metadata:
        return []  # La ausencia puede ser normal

    expected_keys = {"/Author", "/Producer", "/Title", "/Creator", "/CreationDate", "/ModDate", "/Subject", "/Keywords"}
    whitelist_keys = {"/ecv-data"}  # Campos que se consideran "normales" si su contenido es el esperado.
    suspicious_items = []

    for key, value in metadata.items():
        # Ignorar el campo '/Trapped' si su valor es "/False"
        if key == "/Trapped":
            if isinstance(value, str) and value.strip().lower() == "/false":
                continue

        if key in whitelist_keys:
            # Si se trata de '/ecv-data', validamos el contenido
            if isinstance(value, str):
                if not is_ecv_data_normal(value):
                    suspicious_items.append((key, value))
        else:
            # Si el campo no está en el listado esperado,
            # ignoramos si el valor está vacío
            if isinstance(value, str) and value.strip() == "":
                continue
            # De lo contrario, se marca como sospechoso
            if key not in expected_keys:
                suspicious_items.append((key, value))
            # Además, se analiza si el valor incluye indicios de inyección de código
            if isinstance(value, str) and ("<script" in value.lower() or "javascript:" in value.lower()):
                suspicious_items.append((key, value))
    return suspicious_items


def search_pdf_js_actions(pdf_path):
    """
    Revisa la estructura interna del PDF en busca del objeto de acción /OpenAction
    y otros objetos (por ejemplo, en /AA) que indiquen la ejecución de JavaScript.
    Devuelve una lista con tuplas (tipo, código JavaScript) si se encuentra.
    """
    js_actions = []
    try:
        reader = PdfReader(pdf_path)
    except Exception as e:
        return js_actions  # Si no se puede abrir, retorna lista vacía

    # Obtener el objeto root y, si es indirecto, convertirlo
    root = reader.trailer.get("/Root")
    if hasattr(root, "get_object"):
        root = root.get_object()
    if not root:
        return js_actions

    # Revisar el objeto /OpenAction, que se ejecuta al abrir el PDF
    if "/OpenAction" in root:
        try:
            open_action = root["/OpenAction"].get_object()
        except Exception:
            open_action = root["/OpenAction"]
        if isinstance(open_action, dict):
            # Se espera que para acciones JavaScript, la clave /S valga /JavaScript
            if open_action.get("/S", "").lower() == "/javascript":
                js_code = open_action.get("/JS")
                js_actions.append(("OpenAction", js_code))

    # Revisar posibles acciones adicionales (Additional Actions, /AA)
    if "/AA" in root:
        try:
            additional_actions = root["/AA"].get_object()
        except Exception:
            additional_actions = root["/AA"]
        if isinstance(additional_actions, dict):
            for key, action in additional_actions.items():
                try:
                    act_obj = action.get_object()
                except Exception:
                    act_obj = action
                if isinstance(act_obj, dict):
                    if act_obj.get("/S", "").lower() == "/javascript":
                        js_code = act_obj.get("/JS")
                        js_actions.append((f"AA-{key}", js_code))
    return js_actions


def analyze_directory(path):
    """
    Analiza los archivos en un directorio, detecta extensiones sospechosas, calcula tamaños
    y extrae metadatos de imágenes y PDFs.
    """
    if not os.path.exists(path):
        return "El directorio no existe."

    extensions_count = {}
    extensions_size = {}
    suspicious_files = []
    image_metadata = {}  # Diccionario para guardar metadatos de imágenes
    pdf_metadata = {}    # Diccionario para guardar metadatos de PDFs

    # Extensiones peligrosas (ajustables)
    dangerous_extensions = {".bat", ".exe", ".vbs", ".ps1", ".js", ".cmd", ".scr", ".pif"}

    total_files = 0
    total_size = 0

    # Extensiones para extraer metadatos
    image_extensions = {".jpg", ".jpeg", ".png", ".tiff", ".bmp"}
    pdf_extensions = {".pdf"}

    for root, _, files in os.walk(path):
        for file in files:
            total_files += 1
            full_path = os.path.join(root, file)
            try:
                size = os.path.getsize(full_path)
            except Exception as e:
                size = 0
            total_size += size

            ext = os.path.splitext(file)[1].lower()
            extensions_count[ext] = extensions_count.get(ext, 0) + 1
            extensions_size[ext] = extensions_size.get(ext, 0) + size

            if ext in dangerous_extensions:
                suspicious_files.append(full_path)

            # Extraer metadatos para imágenes
            if ext in image_extensions:
                meta = extract_image_metadata(full_path)
                if meta:
                    image_metadata[full_path] = meta

            # Extraer metadatos para PDFs
            if ext in pdf_extensions:
                meta = extract_pdf_metadata(full_path)
                if meta:
                    pdf_metadata[full_path] = meta

    return (extensions_count, extensions_size, suspicious_files,
            total_files, total_size, image_metadata, pdf_metadata)