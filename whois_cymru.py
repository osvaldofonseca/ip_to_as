import socket

PORT = 43
HOSTNAME = 'whois.cymru.com'

def netcat(text_to_send):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(( HOSTNAME, PORT ))
    s.sendall(text_to_send.encode())

    rec_data = []
    while 1:
        data = s.recv(1024)
        if not data:
            break
        rec_data.append(data.decode())

    s.shutdown(socket.SHUT_WR)
    s.close()
    return rec_data

def getInfo(ips):

    text_to_send = "begin\n"
    text_to_send += "\n".join(ips)
    text_to_send += "\nend\n"
    MAX_ATTEMPTS = 5
    worked = False
    attempts = 0
    while (worked == False and attempts < MAX_ATTEMPTS):
        worked = True
        attempts += 1
        try:
            text_recved = netcat(text_to_send)
        except:
            worked = False

    query_result = "".join(text_recved)
    return query_result


