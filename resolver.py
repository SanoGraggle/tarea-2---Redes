import socket
from dnslib import DNSRecord
from dnslib import QTYPE, CLASS
import dnslib
from dnslib import DNSRecord 


ROOT_SERVER_IP = "192.33.4.12"
DNS_PORT = 53


cache_history = []  
cache_counter = {}  
cache = {}          

def actualizar_cache(qname, ip):
    
    cache_history.append(qname)
    if len(cache_history) > 20:
        cache_history.pop(0)
    
    if qname in cache_counter:
        cache_counter[qname] += 1
    else:
        cache_counter[qname] = 1

    recientes = {}
    for dom in cache_history:
        recientes[dom] = recientes.get(dom, 0) + 1
    top3 = sorted(recientes, key=recientes.get, reverse=True)[:3]
    for dom in list(cache.keys()):
        if dom not in top3:
            del cache[dom]
    cache[qname] = ip

def construir_respuesta_cache(mensaje_consulta, ip):
    q = DNSRecord.parse(mensaje_consulta)
    reply = q.reply()
    reply.add_answer(
        dnslib.RR(
            rname=q.questions[0].qname,
            rtype=QTYPE.A,
            rclass=CLASS.IN,
            ttl=60,
            rdata=dnslib.A(ip)
        )
    )
    return reply.pack()

def resolver(mensaje_consulta):
    try:
        q = DNSRecord.parse(mensaje_consulta)
        qname = str(q.questions[0].get_qname())
    except Exception:
        qname = None

    if qname in cache:
        print(f"(debug) Respondiendo desde caché para '{qname}' con IP '{cache[qname]}'")
        return construir_respuesta_cache(mensaje_consulta, cache[qname])

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
        for answer in parsed["Answer"]:
            if answer["type"] == "A":
                ip = answer["rdata"]
                actualizar_cache(qname, ip)
                return data

        ns_names = [auth["rdata"] for auth in parsed["Authority"] if auth["type"] == "NS"]
        additional_ips = [add["rdata"] for add in parsed["Additional"] if add["type"] == "A"]

        if additional_ips:
            servidor_ip = additional_ips[0]
            print(f"(debug) Consultando a '{servidor_ip}' con nueva IP de Additional: '{additional_ips[0]}'")
            continue

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
        return None

def parse_dns_message(data):
    d = DNSRecord.parse(data)
    result = {}

    if d.questions:
        result["Qname"] = str(d.questions[0].get_qname())
    else:
        result["Qname"] = None

    result["ANCOUNT"] = d.header.a
    result["NSCOUNT"] = d.header.auth
    result["ARCOUNT"] = d.header.ar

    result["Answer"] = []
    for rr in d.rr:
        result["Answer"].append({
            "name": str(rr.rname),
            "type": QTYPE.get(rr.rtype),
            "class": CLASS.get(rr.rclass),
            "ttl": rr.ttl,
            "rdata": str(rr.rdata)
        })

    result["Authority"] = []
    for rr in d.auth:
        result["Authority"].append({
            "name": str(rr.rname),
            "type": QTYPE.get(rr.rtype),
            "class": CLASS.get(rr.rclass),
            "ttl": rr.ttl,
            "rdata": str(rr.rdata)
        })

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