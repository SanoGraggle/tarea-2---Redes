import socket
from dnslib import DNSRecord


def send_dns_message(address, port):
     qname = "example.com"
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
        print(f"Recibido mensaje de {client_addr}: {data}")
        # Aquí puedes procesar el mensaje y responder si es necesario