import psutil

def scan_network_connections():
    """Devuelve una lista de conexiones TCP establecidas con su PID, programa y ubicación del ejecutable."""
    connections = []
    
    for conn in psutil.net_connections(kind="tcp"):
        local_ip = conn.laddr.ip if conn.laddr else "N/A"
        local_port = conn.laddr.port if conn.laddr else "N/A"
        remote_ip = conn.raddr.ip if conn.raddr else "N/A"
        remote_port = conn.raddr.port if conn.raddr else "N/A"

        pid = conn.pid if conn.pid is not None else "N/A"
        process_name = "Desconocido"
        process_path = "No accesible"

        try:
            if isinstance(pid, int):
                process = psutil.Process(pid)
                process_name = process.name()  # Nombre del programa
                process_path = process.exe()  # Ruta del ejecutable
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            process_name = "No accesible"
            process_path = "No accesible"

        connections.append({
            "local": f"{local_ip}:{local_port}",
            "remote": f"{remote_ip}:{remote_port}",
            "state": conn.status,
            "pid": pid,
            "program": process_name,
            "path": process_path
        })
    
    return connections
