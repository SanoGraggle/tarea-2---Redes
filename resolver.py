import socket
from dnslib import DNSRecord
from dnslib import QTYPE, CLASS
import dnslib
from dnslib import DNSRecord 

 # Modificar el mensaje de pregunta (opción 1) 
#dns_query.add_answer(RR(qname, QTYPE.A, rdata=A(ip_answer)))

ROOT_SERVER_IP = "192.33.4.12"
DNS_PORT = 53

def resolver(mensaje_consulta):
    # Comenzar con el root
    servidor_ip = ROOT_SERVER_IP
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        try:
            sock.sendto(mensaje_consulta, (servidor_ip, DNS_PORT))
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            sock.close()
            return None
        sock.close()

        parsed = parse_dns_message(data)
        qname = parsed["Qname"]
        ns_name = parsed["Authority"][0]["name"] if parsed["Authority"] else None
        print(f"(debug) Consultando '{qname}' a '{ns_name}' con dirección IP '{servidor_ip}'")
        # Si hay respuesta tipo A en Answer, retornar el mensaje recibido
        for answer in parsed["Answer"]:
            if answer["type"] == "A":
                return data

        # Si hay delegación (NS en Authority)
        ns_names = [auth["rdata"] for auth in parsed["Authority"] if auth["type"] == "NS"]
        additional_ips = [add["rdata"] for add in parsed["Additional"] if add["type"] == "A"]

        # Si hay IP en Additional, reenviar la query a esa IP (solo la primera)
        if additional_ips:
            servidor_ip = additional_ips[0]
            print(f"(debug) Consultando a '{servidor_ip}' con nueva IP de Additional: '{additional_ips[0]}'")
            continue

        # Si no hay IP, resolver el nombre del NS recursivamente
        found_ns_ip = False
        for ns_name in ns_names:
            ns_query = DNSRecord.question(ns_name).pack()
            ns_ip_response = resolver(ns_query)
            if ns_ip_response:
                ns_ip_parsed = parse_dns_message(ns_ip_response)
                for ans in ns_ip_parsed["Answer"]:
                    if ans["type"] == "A":
                        print(f"(debug) Consultando a '{servidor_ip}' con IP resuelta de Authority: '{ans['rdata']}'")
                        servidor_ip = ans["rdata"]
                        found_ns_ip = True
                        break
            if found_ns_ip:
                break
        if found_ns_ip:
            continue
        # Si no se pudo resolver, salir
        return None

def parse_dns_message(data):
    d = DNSRecord.parse(data)
    result = {}

    # Qname
    if d.questions:
        result["Qname"] = str(d.questions[0].get_qname())
    else:
        result["Qname"] = None

    # Contadores
    result["ANCOUNT"] = d.header.a
    result["NSCOUNT"] = d.header.auth
    result["ARCOUNT"] = d.header.ar

    # Answer
    result["Answer"] = []
    for rr in d.rr:
        result["Answer"].append({
            "name": str(rr.rname),
            "type": QTYPE.get(rr.rtype),
            "class": CLASS.get(rr.rclass),
            "ttl": rr.ttl,
            "rdata": str(rr.rdata)
        })

    # Authority
    result["Authority"] = []
    for rr in d.auth:
        result["Authority"].append({
            "name": str(rr.rname),
            "type": QTYPE.get(rr.rtype),
            "class": CLASS.get(rr.rclass),
            "ttl": rr.ttl,
            "rdata": str(rr.rdata)
        })

    # Additional
    result["Additional"] = []
    for rr in d.ar:
        result["Additional"].append({
            "name": str(rr.rname),
            "type": QTYPE.get(rr.rtype),
            "class": CLASS.get(rr.rclass),
            "ttl": rr.ttl,
            "rdata": str(rr.rdata)
        })

    return result


def send_dns_message(query_name, address, port):
    # Acá ya no tenemos que crear el encabezado porque dnslib lo hace por nosotros, por default pregunta por el tipo A
    qname = query_name
    q = DNSRecord.question(qname)
    server_address = (address, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # lo enviamos, hacemos cast a bytes de lo que resulte de la función pack() sobre el mensaje
        sock.sendto(bytes(q.pack()), server_address)
        # En data quedará la respuesta a nuestra consulta
        data, _ = sock.recvfrom(4096)
        # le pedimos a dnslib que haga el trabajo de parsing por nosotros
        d = DNSRecord.parse(data)
    finally:
        sock.close()
    # Ojo que los datos de la respuesta van en en una estructura de datos
    return d



if __name__ == "__main__":
    address = ("localhost", 8000)
    buffer_size = 4096
    dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_socket.bind(address)

    print("Esperando mensajes DNS en el puerto 8000...")
    while True:
        data, client_addr = dns_socket.recvfrom(buffer_size)
        respuesta = resolver(data)
        if respuesta:
            dns_socket.sendto(respuesta, client_addr)