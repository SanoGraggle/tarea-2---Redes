import socket
from dnslib import DNSRecord
from dnslib import QTYPE, CLASS
import dnslib
from dnslib.dns import RR, A
from dnslib import DNSRecord, DNSHeader, DNSQuestion 

 # Modificar el mensaje de pregunta (opción 1) 
#dns_query.add_answer(RR(qname, QTYPE.A, rdata=A(ip_answer)))

ROOT_SERVER_IP = "192.33.4.12"
DNS_PORT = 53

def resolver(mensaje_consulta):
    servidor_ip = ROOT_SERVER_IP
    DNS_PORT = 53

    # 1. Enviar la consulta al servidor actual (inicialmente el root)
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

    # 2. Si hay respuesta tipo A en Answer, retornar el mensaje recibido
    for answer in parsed["answers"]:
        if answer["type"] == "A":
            return data

    # 3. Si hay delegación (NS en Authority)
    ns_names = [auth["rdata"] for auth in parsed["authority"] if auth["type"] == "NS"]

    # Buscar IPs en Additional
    additional_ips = [add["rdata"] for add in parsed["additional"] if add["type"] == "A"]

    # 3.i. Si hay IP en Additional, reenviar la query a esa IP
    if additional_ips:
        next_ip = additional_ips[0]
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        try:
            sock.sendto(mensaje_consulta, (next_ip, DNS_PORT))
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            sock.close()
            return None
        sock.close()
        # Recursivamente procesar la respuesta
        parsed = parse_dns_message(data)
        for answer in parsed["answers"]:
            if answer["type"] == "A":
                return data
        # Si no hay respuesta tipo A, repetir el proceso
        return resolver(mensaje_consulta)

    # 3.ii. Si no hay IP, resolver el nombre del NS recursivamente
    for ns_name in ns_names:
        ns_query = DNSRecord.question(ns_name).pack()
        ns_ip_response = resolver(ns_query)
        if ns_ip_response:
            ns_ip_parsed = parse_dns_message(ns_ip_response)
            for ans in ns_ip_parsed["answers"]:
                if ans["type"] == "A":
                    # Ahora tenemos la IP del NS, reenviamos la consulta original
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(5)
                    try:
                        sock.sendto(mensaje_consulta, (ans["rdata"], DNS_PORT))
                        data, _ = sock.recvfrom(4096)
                    except socket.timeout:
                        sock.close()
                        return None
                    sock.close()
                    parsed = parse_dns_message(data)
                    for answer in parsed["answers"]:
                        if answer["type"] == "A":
                            return data
                    # Si no hay respuesta tipo A, repetir el proceso
                    return resolver(mensaje_consulta)

    # 4. Otro tipo de respuesta: ignorar
    return None

def parse_dns_message(data):
    d = DNSRecord.parse(data)

    result = {}

    # HEADER SECTION
    result["qr_flag"] = d.header.get_qr()
    result["QDCOUNT"] = d.header.q
    result["ANCOUNT"] = d.header.a
    result["NSCOUNT"] = d.header.auth
    result["ARCOUNT"] = d.header.ar

    # QUERY SECTION
    result["queries"] = []
    for q in d.questions:
        result["queries"].append({
            "qname": str(q.get_qname()),
            "qclass": CLASS.get(q.qclass),
            "qtype": QTYPE.get(q.qtype)
        })

    # ANSWER SECTION
    result["answers"] = []
    for rr in d.rr:
        result["answers"].append({
            "name": str(rr.rname),
            "type": QTYPE.get(rr.rtype),
            "class": CLASS.get(rr.rclass),
            "ttl": rr.ttl,
            "rdata": str(rr.rdata)
        })

    # AUTHORITY SECTION
    result["authority"] = []
    for rr in d.auth:
        rr_dict = {
            "name": str(rr.rname),
            "type": QTYPE.get(rr.rtype),
            "class": CLASS.get(rr.rclass),
            "ttl": rr.ttl,
            "rdata": str(rr.rdata)
        }
        # Si es SOA o NS puedes agregar más detalles si quieres
        result["authority"].append(rr_dict)

    # ADDITIONAL SECTION
    result["additional"] = []
    for rr in d.ar:
        result["additional"].append({
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
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    proxy_socket.bind(address)

    print("Esperando mensajes UDP en el puerto 8000...")
    while True:
        data, client_addr = proxy_socket.recvfrom(buffer_size)
        respuesta = resolver(data)
        if respuesta:
            proxy_socket.sendto(respuesta, client_addr)