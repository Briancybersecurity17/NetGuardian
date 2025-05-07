import psutil

def scan_network_connections():
    """Devuelve una lista de conexiones TCP establecidas, cada una en forma de diccionario."""
    connections = []
    for conn in psutil.net_connections(kind="tcp"):
        # Procesa la dirección local (laddr)
        if conn.laddr and isinstance(conn.laddr, tuple) and len(conn.laddr) >= 2:
            local_ip = conn.laddr[0]
            local_port = conn.laddr[1]
        else:
            local_ip = "N/A"
            local_port = "N/A"

        # Procesa la dirección remota (raddr)
        if conn.raddr and isinstance(conn.raddr, tuple) and len(conn.raddr) >= 2:
            remote_ip = conn.raddr[0]
            remote_port = conn.raddr[1]
        else:
            remote_ip = "N/A"
            remote_port = "N/A"

        connections.append({
            "local": f"{local_ip}:{local_port}",
            "remote": f"{remote_ip}:{remote_port}",
            "state": conn.status
        })
    return connections