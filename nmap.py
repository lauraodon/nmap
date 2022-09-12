"""
FIAP
Defesa Cibernetica - 1TDCF - 2021
Development e Coding for Security
Prof. MS. Fabio H. Cabrini
Atividade: Checkpoint NMAP em python
Alunos:
    Laura Giancoli Aschenbrenner - RM 87194
    Matheus Lambert Moreira - RM 87079
"""

import nmap
import socket

# Definimos uma funcao de um port scan no protocolo TCP no ativo recebido
def nmapTCP(host, ip, port):
    try:
        result = []
        NMAPSCAN = nmap.PortScanner()
        NMAPSCAN.scan(hosts=ip, ports=str(port), arguments='-Pn')
        state = NMAPSCAN[ip]['tcp'][int(port)]['state']
        name = NMAPSCAN[ip]['tcp'][int(port)]['name']
        result.append({'port': port, 'state': state, 'name': name})
        print("[*] tcp/" + port + " " + \
                state + " " + name)
        with open("portasTCP.txt", 'a') as txt_file:
            print(result, file=txt_file)

    except:
        print("Não foi possivel obter informacoes suficientes sobre a porta "\
                + port)
        pass

# Define uma funcao que executa um port scan no protocolo UDP no ativo recebido
def nmapUDP(host, ip, port):
    try:
        result = []
        scanner = nmap.PortScanner()
        scanner.scan(hosts=ip, ports=str(port), arguments='-Pn -sU ', sudo=True)
        state = scanner[ip]['udp'][int(port)]['state']
        name = scanner[ip]['udp'][int(port)]['name']
        result.append({'port': port, 'state': state, 'name': name})
        print("[*] udp/" + port + " " + \
                state + " " + name)
        with open("portasUDP.txt", 'a') as txt_file:
            print(result, file=txt_file)

    except:
        print("Não foi possível realizar o UDP scan na(s) porta(s): "\
                + port)
        pass

# Armazena as entradas do usuario
host = input("Host: ")
ports = input("Porta: ")
ports = ports.split()
protocolo = input("Procotolo: ")

# Checa se o valor das entradas do usuario nao esta vazio
if not host or not ports or not protocolo:
    print("falta coisa")
    exit(0)
else:
    if (protocolo == "TCP"):
        ip = socket.gethostbyname(host)
        print("Resultado " + host + "(" + ip +")")
        for port in ports:
            nmapTCP(host, ip, port)

    elif (protocolo == "UDP"):
        ip = socket.gethostbyname(host)
        print("Resultado UDP:" + host + "(" + ip +")")
        for port in ports:
            nmapUDP(host, ip, port)
