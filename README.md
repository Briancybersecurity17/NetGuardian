# NetGuardian 🛡️
🔹 Introducción
NetGuardian es una herramienta de seguridad informática diseñada para Windows que permite analizar directorios, extraer y verificar metadatos, escanear conexiones de red, generar y verificar contraseñas, e identificar potenciales riesgos en archivos PDF.
Su objetivo es facilitar la detección de archivos sospechosos, identificar inyecciones de código en documentos y ayudar a los usuarios a fortalecer sus credenciales.

Antes que nada dentro de la carpeta modulos hay una carpeta llamada "dist" ahi es donde ya  tienen empaquetado en un ejecutable el programa. De todas maneras si prefieren ejecutarlo desde la CMD el modulo que deben ejecutar es gui.py
Características
✅ Análisis de directorios → Identifica archivos potencialmente sospechosos por extensión y tamaño.
✅ Extracción y evaluación de metadatos en imágenes y PDFs → Examina archivos en busca de contenido anómalo o riesgos potenciales.
✅ Detección de JavaScript en PDFs → Identifica código incrustado en documentos que pueda ejecutar acciones automáticamente.
✅ Escaneo de conexiones de red → Muestra información sobre conexiones TCP activas en el sistema.
✅ Generación segura de contraseñas → Crea contraseñas aleatorias robustas pidiendo al usuario que ingrese la longitud y el tipo de hash que quiere aplicar a la contraseña (sha256, sha512, bcrypt).
✅ Verificación de filtración de contraseñas → Compara contraseñas con bases de datos de filtraciones a través de la API de Have I Been Pwned.
✅ Interfaz gráfica intuitiva → Accede a todas las funciones desde una ventana accesible y organizada.


🔧 Instalación
1️⃣ Requisitos
- Windows 10/11
- Python 3.11+
- Dependencias indicadas en requirements.txt
2️⃣ Instalar Dependencias
Antes de ejecutar la herramienta, instala los paquetes necesarios con:

pip install -r requirements.txt

Si deseas instalar cada módulo individualmente, puedes usar:

pip install PyPDF2 reportlab Pillow psutil bcrypt requests

python gui.py


🎮 Uso
📂 Análisis de Directorios
Detecta archivos sospechosos por extensión y tamaño, además de analizar metadatos en imágenes y PDFs.
Desde la interfaz gráfica, haz clic en "Analiza directorio" y selecciona la carpeta deseada.
🖼️ Extracción de Metadatos
- Imágenes: Evalúa información EXIF.
- PDFs: Inspecciona metadata oculta y objetos de acción (/OpenAction).
🛜 Escaneo de Red
Revisa las conexiones TCP establecidas con detalles sobre IPs locales y remotas.
Haz clic en "Escanea tu red" para obtener un informe.
🔑 Gestión de Contraseñas
- Generar contraseña: Usa el botón "Genera tu contraseña" para obtener una clave segura con su has correspondiente.
- Verificar contraseñas: Si una clave ha sido filtrada, NetGuardian te notificará.
📄 Formato de Reportes
El resultado de los análisis puede guardarse automáticamente en TXT o CSV.

🛠️ Módulos
| Módulo                |                 Descripción                       | 
| directory_analyzer.py | Analiza directorios, evalúa metadatos y detecta   |
|                       | archivos sospechosos.                             | 
| network_scanner.py    | Escanea conexiones TCP activas en el sistema.     |
| password_generator.py | Genera contraseñas seguras con hashing SHA-256,   |        
|                       | SHA-512 o bcrypt.                                 |  
| verificar_password.py | Verifica si una contraseña ha sido filtrada usando|
|                       | Have I Been Pwned.                                | 
| gui.py                | Interfaz gráfica que gestiona todas las funciones.| 



📝 Notas Finales
- NetGuardian está optimizado para Windows.
- Se recomienda ejecutarlo en un entorno seguro antes de analizar archivos   
  críticos.
- No almacena contraseñas, solo verifica su integridad de forma segura.
- Las conexiones de red mostradas son información pública del sistema operativo,
  sin modificar datos internos.
📌 Desarrollado por: Brian Almada



