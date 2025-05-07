import tkinter as tk
from tkinter import filedialog, scrolledtext
import csv
import os

# Importa las funciones de tus módulos
from password_generator import generate_password, hash_password
from directory_analyzer import analyze_directory, is_image_metadata_suspicious, is_pdf_metadata_suspicious, search_pdf_js_actions # Asumiendo que ésta es la función principal
from network_scanner import scan_network_connections  # O la función que hayas definido
from verificar_password import check_password_pwned  # Función para verificar filtrado

#########################################
# Variables Globales para Ingreso Dinámico
#########################################
# Esta variable almacenará la función que debe procesar el dato ingresado.
current_input_handler = None
global_pwd_length = None

#########################################
# Funciones de Guardado y Actualización
#########################################

def save_report():
    """Guarda el contenido del área de resultados en el formato seleccionado si el checkbox está activado."""
    if auto_save_var.get():
        format_selected = format_var.get()
        file_extension = ".csv" if format_selected == "CSV" else ".txt"
        
        file_path = filedialog.asksaveasfilename(
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv")],
            title="Guardar reporte"
        )
        if file_path:
            if not file_path.endswith(file_extension):
                file_path += file_extension

            with open(file_path, "w", encoding="utf-8", newline="") as file:
                if format_selected == "TXT":
                    file.write(result_text.get("1.0", tk.END))
                else:
                    writer = csv.writer(file)
                    lines = result_text.get("1.0", tk.END).split("\n")
                    for line in lines:
                        writer.writerow([line])
            result_text.config(state="normal")
            result_text.insert(tk.END, f"✅ Reporte guardado en: {file_path}\n")
            result_text.config(state="disabled")

def update_results(text):
    """Actualiza el área de resultados (solamente desde el código)."""
    result_text.config(state="normal")
    result_text.insert(tk.END, text + "\n")
    result_text.config(state="disabled")
    if auto_save_var.get():
        save_report()

#########################################
# Funciones para el Ingreso de Datos
#########################################

def request_generate_password():
    """
    Prepara la interfaz para que el usuario ingrese la longitud deseada para la contraseña.
    """
    
    cancel_pending_input()  # Cancela cualquier ingreso pendiente
    result_text.config(state="normal")
    result_text.delete("1.0", tk.END)
    result_text.config(state="disabled")
    global current_input_handler
    current_input_handler = handle_generate_password_length_input
    command_label.config(text="Ingresa longitud de pwd deseada (>= 8):")

def handle_generate_password_length_input(user_input):
    """
    Procesa el input de longitud de la contraseña.
    Verifica que el valor ingresado sea un número entero y mayor o igual a 8.
    """
    global current_input_handler, global_pwd_length
    try:
        length = int(user_input)
        if length < 8:
            update_results("La longitud debe ser mayor o igual a 8. Inténtalo de nuevo.")
            return
        global_pwd_length = length
        # Ahora pasa al siguiente paso: solicitar el tipo de hash
        current_input_handler = handle_generate_password_hash_input
        command_label.config(text="Ingresa hash deseado (sha256, sha512, bcrypt):")
    except ValueError:
        update_results("Por favor, ingresa un número válido para la longitud.")
        return


def handle_generate_password_hash_input(user_input):
    """
    Procesa el input para el tipo de hash y concreta la generación de la contraseña.
    """
    global current_input_handler, global_pwd_length
    hash_choice = user_input.strip().lower()
    if hash_choice not in ["sha256", "sha512", "bcrypt"]:
        update_results("Tipo de hash no soportado. Elige entre: sha256, sha512 o bcrypt.")
        return
    # Genera la contraseña con la longitud especificada, asegurando que inicia con mayúscula
    password = generate_password(length=global_pwd_length, use_special_chars=True)
    hashed = hash_password(password, hash_choice)
    msg = f"Contraseña generada: {password}\nHash ({hash_choice}): {hashed}"
    update_results(msg)
    # Restaura la etiqueta de comandos y limpia el handler
    command_label.config(text="Comando / Entrada:")
    current_input_handler = None


# Esta función se invoca cuando el usuario pulsa el botón "Verifica contraseña".
def request_verify_password():
    """Configura el ingreso de datos para verificar la contraseña.
    Cambia la etiqueta del campo de entrada y asigna el handler adecuado.
    """
    result_text.config(state="normal")
    result_text.delete("1.0", tk.END)
    result_text.config(state="disabled")
    global current_input_handler
    current_input_handler = handle_verify_password_input  # El handler específico
    command_label.config(text="Ingrese la contraseña a verificar:")

def handle_verify_password_input(user_input):
    """Procesa la contraseña ingresada para verificar filtrado."""
    cancel_pending_input()  # Cancela cualquier ingreso pendiente
    result_text.config(state="normal")
    result_text.delete("1.0", tk.END)
    result_text.config(state="disabled")
    password = user_input.strip()
    if not password:
        update_results("Por favor, ingrese la contraseña a verificar.")
        return
    try:
        result = check_password_pwned(password)
        update_results(result)
    except Exception as e:
        update_results(f"Error al verificar la contraseña: {e}")
    # Restaura el texto por defecto de la etiqueta
    command_label.config(text="Comando / Entrada:")


def handle_network_scan():
    try:
        cancel_pending_input()  # Cancela cualquier ingreso pendiente
        result_text.config(state="normal")
        result_text.delete("1.0", tk.END)
        result_text.config(state="disabled")
        
        conns = scan_network_connections()
        
        if not conns:
            update_results("No se encontraron conexiones TCP establecidas.")
        else:
            # Suponiendo que ya sean diccionarios...
            conns.sort(key=lambda x: (x["state"], x["local"]))
            header = f"{'Local Address':<45} | {'Remote Address':<45} | {'Estado':<12}"
            separator = "-" * len(header)
            output_lines = [header, separator]
            for c in conns:
                line = f"{c['local']:<45} | {c['remote']:<45} | {c['state']:<12}"
                output_lines.append(line)
            result = "\n".join(output_lines)
            update_results(result)
    except Exception as e:
        update_results(f"Error al escanear la red: {e}")


def handle_directory_analysis():
    cancel_pending_input()  # Cancela cualquier ingreso pendiente
    result_text.config(state="normal")
    result_text.delete("1.0", tk.END)
    result_text.config(state="disabled")
    path = filedialog.askdirectory(title="Seleccione el directorio a analizar")
    if not path:
        update_results("No se seleccionó ningún directorio.")
        return

    result = analyze_directory(path)
    if isinstance(result, str):
        update_results(result)
        return

    (extensions_count, extensions_size, suspicious_files,
     total_files, total_size, image_metadata, pdf_metadata) = result

    # Función local para convertir tamaño a un formato legible.
    def format_size(size):
        for unit in ['B','KB','MB','GB','TB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} PB"

    summary = ""
    summary += "=" * 50 + "\n"
    summary += "          Resumen del Directorio\n"
    summary += "=" * 50 + "\n"
    summary += f"Directorio analizado : {path}\n"
    summary += f"Total de archivos    : {total_files}\n"
    summary += f"Tamaño total         : {format_size(total_size)}\n\n"

    summary += "-" * 50 + "\n"
    summary += "      Metadatos Detectados\n"
    summary += "-" * 50 + "\n"
    summary += f"  Imágenes : {len(image_metadata)}\n"
    summary += f"  PDF      : {len(pdf_metadata)}\n"
    summary += "-" * 50 + "\n\n"

    summary += "=" * 50 + "\n"
    summary += "   Conteo y Tamaño por Extensión\n"
    summary += "=" * 50 + "\n"
    summary += f"{'Extensión':<15} {'Archivos':>10} {'Tamaño':>15}\n"
    summary += "-" * 50 + "\n"
    for ext, count in sorted(extensions_count.items()):
        ext_display = ext if ext else "[sin extensión]"
        size_display = format_size(extensions_size.get(ext, 0))
        summary += f"{ext_display:<15} {count:>10} {size_display:>15}\n"
    summary += "-" * 50 + "\n\n"

    if suspicious_files:
        summary += "¡Alerta! Archivos con Extensiones Sospechosas:\n"
        summary += "-" * 50 + "\n"
        for file_path in suspicious_files:
            summary += f"{file_path}\n"
        summary += "-" * 50 + "\n\n"
    else:
        summary += "No se detectaron archivos con extensiones sospechosas.\n\n"

    # Análisis de metadatos sospechosos en imágenes
    suspicious_image_meta_details = {}
    for file_path, meta in image_metadata.items():
        suspicious_items = is_image_metadata_suspicious(meta)
        if suspicious_items:
            suspicious_image_meta_details[file_path] = suspicious_items

    if suspicious_image_meta_details:
        summary += "¡Alerta! Metadatos Sospechosos en Imágenes:\n"
        summary += "-" * 50 + "\n"
        for file_path, items in suspicious_image_meta_details.items():
            summary += f"{file_path}:\n"
            for key, value in items:
                summary += f"    Clave {key}: {value}\n"
            summary += "\n"
        summary += "-" * 50 + "\n\n"
    else:
        summary += "No se detectaron metadatos sospechosos en imágenes.\n\n"

    # Análisis de metadatos sospechosos en archivos PDF
    suspicious_pdf_meta_details = {}
    for file_path, meta in pdf_metadata.items():
        suspicious_items = is_pdf_metadata_suspicious(meta)
        if suspicious_items:
            suspicious_pdf_meta_details[file_path] = suspicious_items

    if suspicious_pdf_meta_details:
        summary += "¡Alerta! Metadatos Sospechosos en Archivos PDF:\n"
        summary += "-" * 50 + "\n"
        for file_path, items in suspicious_pdf_meta_details.items():
            summary += f"{file_path}:\n"
            for key, value in items:
                summary += f"    Campo {key}: {value}\n"
            summary += "\n"
        summary += "-" * 50 + "\n\n"
    else:
        summary += "No se detectaron metadatos sospechosos en archivos PDF.\n\n"

    # Nueva sección: Buscar acciones JavaScript en la estructura interna del PDF
    suspicious_pdf_actions = {}
    for pdf_path in pdf_metadata.keys():
        actions = search_pdf_js_actions(pdf_path)
        if actions:
            suspicious_pdf_actions[pdf_path] = actions

    if suspicious_pdf_actions:
        summary += "¡Alerta! Acciones JavaScript detectadas en PDFs:\n"
        summary += "-" * 50 + "\n"
        for pdf_path, actions in suspicious_pdf_actions.items():
            summary += f"{pdf_path}:\n"
            for action_type, js_code in actions:
                summary += f"    {action_type}: {js_code}\n"
            summary += "\n"
        summary += "-" * 50 + "\n\n"
    else:
        summary += "No se detectaron acciones JavaScript en archivos PDF.\n\n"

    update_results(summary)


def cancel_pending_input():
    global current_input_handler
    # Reinicia la entrada interactiva y vuelve al estado por defecto.
    current_input_handler = None
    command_label.config(text="Comando / Entrada:")
    command_entry.delete(0, tk.END)


def handle_command():
    global current_input_handler
    if current_input_handler is None:
        update_results("No se ha solicitado ingreso de datos.")
    else:
        user_input = command_entry.get().strip()
        current_input_handler(user_input)
    command_entry.delete(0, tk.END)

#########################################
# Configuración de la Ventana
#########################################

root = tk.Tk()
root.title("NetGuardian 🛡️ by Almada Brian")
root.geometry("1024x768")
root.configure(bg="#1a1a1a")

# --- Top Frame: Checkbox y Selección de Formato ---
top_frame = tk.Frame(root, bg="#1a1a1a")
top_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

auto_save_var = tk.BooleanVar()
checkbox_save = tk.Checkbutton(top_frame,
                               text="Guardar resultado automáticamente",
                               var=auto_save_var,
                               fg="white", bg="#333333", selectcolor="black")
checkbox_save.pack(side=tk.LEFT, anchor="w")

format_var = tk.StringVar(value="TXT")
format_menu = tk.OptionMenu(top_frame, format_var, "TXT", "CSV")
format_menu.pack(side=tk.LEFT, padx=10)

# --- Título ---
title_label = tk.Label(root, text="NetGuardian 🛡️", font=("Helvetica", 20, "bold"), fg="red", bg="#1a1a1a")
title_label.pack(pady=10)

# --- Frame de Botones ---
button_frame = tk.Frame(root, bg="#1a1a1a")
button_frame.pack(pady=10, fill=tk.X, padx=10)  # Se asegura de llenar horizontalmente

btn_style = {"width": 25, "height": 2, "bg": "#990000", "fg": "white", "font": ("Helvetica", 12, "bold")}

btn_contraseña = tk.Button(button_frame,
                           text="Genera tu contraseña",
                           command=request_generate_password,
                           **btn_style)
btn_contraseña.grid(row=0, column=0, padx=10, pady=5, sticky="nsew")

btn_directorio = tk.Button(button_frame,
    text="Analiza directorio",
    command=handle_directory_analysis,
    **btn_style
)
btn_directorio.grid(row=0, column=1, padx=10, pady=5, sticky="nsew")

btn_red = tk.Button(button_frame,
    text="Escanea tu red",
    command=handle_network_scan,  # Se usa el handler creado
    **btn_style
)
btn_red.grid(row=0, column=2, padx=10, pady=5, sticky="nsew")

btn_contraseña_filtrada = tk.Button(button_frame,
                                    text="Verifica contraseña",
                                    command=request_verify_password,
                                    **btn_style)
btn_contraseña_filtrada.grid(row=0, column=3, padx=10, pady=5, sticky="nsew")

# Configurar las columnas para que se expandan equitativamente
for col in range(4):
    button_frame.grid_columnconfigure(col, weight=1)


# --- Área de Resultados ---
result_frame = tk.Frame(root, bg="#1a1a1a")
result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

result_text = scrolledtext.ScrolledText(result_frame,
                                         wrap=tk.WORD,
                                         fg="white",
                                         bg="#000000",
                                         insertbackground="white",
                                         state="disabled")  # De sólo lectura
result_text.pack(fill=tk.BOTH, expand=True)

# --- Área de Comandos / Entrada de Datos ---
command_frame = tk.Frame(root, bg="#1a1a1a")
command_frame.pack(fill=tk.X, padx=10, pady=10)

command_label = tk.Label(command_frame,
                         text="Comando / Entrada:",
                         fg="white",
                         bg="#1a1a1a",
                         font=("Helvetica", 12))
command_label.pack(side=tk.LEFT, padx=5)

command_entry = tk.Entry(command_frame, width=50, font=("Helvetica", 12))
command_entry.pack(side=tk.LEFT, padx=5)

command_button = tk.Button(command_frame,
                           text="Ejecutar",
                           command=handle_command,
                           bg="#990000", fg="white", font=("Helvetica", 12, "bold"))
command_button.pack(side=tk.LEFT, padx=5)

# Ejecutar la aplicación
root.mainloop()