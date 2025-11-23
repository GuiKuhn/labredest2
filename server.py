#!/usr/bin/env python3

import socket
import struct
import threading
import time
import csv
import argparse
import os
import sys
import signal
from datetime import datetime
from collections import defaultdict, Counter

INTERFACE_PADRAO = "tun0"
CSV_INTERNET = "internet.csv"
CSV_TRANSPORTE = "transporte.csv"
CSV_APLICACAO = "aplicacao.csv"

FORCAR_FLUSH = True  # força flush/persistência para que 'cat' mostre em tempo real

# portas de cada um dos protocolos
HTTP_PORTS = {80, 8080, 8000, 443}
DNS_PORTS = {53}
DHCP_PORTS = {67, 68}
NTP_PORTS = {123}

trava_contadores = threading.Lock()
contadores_proto = Counter()  # contador do numero de protocolos
trava_estatisticas_clientes = threading.Lock()
estatisticas_clientes = defaultdict(lambda: {
    "remotes": defaultdict(lambda: {"packets": 0, "bytes": 0, "ports": Counter()}),
    "total_packets": 0,
    "total_bytes": 0
})
executando = True

arquivos_csv = {}
escritores_csv = {}

def iso_now():
    return datetime.utcnow().isoformat(sep=' ', timespec='seconds')


def decodificar_segura(data, maxlen=256):
    try:
        return data[:maxlen].decode('utf-8', errors='replace')
    except Exception:
        return "<binary>"


def garantir_cabecalhos_csv():
    global arquivos_csv, escritores_csv
    # camada de rede (ipv4, ipv6 e icmp) salvo em internet.csv
    if CSV_INTERNET not in arquivos_csv:
        f = open(CSV_INTERNET, "a", newline='', buffering=1)
        writer = csv.writer(f)
        if os.path.getsize(CSV_INTERNET) == 0:
            writer.writerow([
                "data_hora",
                "protocolo",
                "ip_origem",
                "ip_destino",
                "numero_protocolo",
                "info_adicional",
                "tamanho_total_bytes"
            ])
            if FORCAR_FLUSH:
                f.flush()
                os.fsync(f.fileno())
        arquivos_csv[CSV_INTERNET] = f
        escritores_csv[CSV_INTERNET] = writer

    # camada de transporte (tcp, udp) salvo em transporte.csv
    if CSV_TRANSPORTE not in arquivos_csv:
        f = open(CSV_TRANSPORTE, "a", newline='', buffering=1)
        writer = csv.writer(f)
        if os.path.getsize(CSV_TRANSPORTE) == 0:
            writer.writerow([
                "data_hora",
                "protocolo",
                "ip_origem",
                "porta_origem",
                "ip_destino",
                "porta_destino",
                "tamanho_total_bytes"
            ])
            if FORCAR_FLUSH:
                f.flush()
                os.fsync(f.fileno())
        arquivos_csv[CSV_TRANSPORTE] = f
        escritores_csv[CSV_TRANSPORTE] = writer

    # camada de aplicação (http, dns, dhcp, ntp, outro) salvo em aplicacao.csv
    if CSV_APLICACAO not in arquivos_csv:
        f = open(CSV_APLICACAO, "a", newline='', buffering=1)
        writer = csv.writer(f)
        if os.path.getsize(CSV_APLICACAO) == 0:
            writer.writerow([
                "data_hora",
                "protocolo",
                "info"
            ])
            if FORCAR_FLUSH:
                f.flush()
                os.fsync(f.fileno())
        arquivos_csv[CSV_APLICACAO] = f
        escritores_csv[CSV_APLICACAO] = writer

# método pra escrever no csv em tempo real
def persistir_csv(name):
    if FORCAR_FLUSH:
        f = arquivos_csv.get(name)
        if f:
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass

def analisar_frame_ethernet(packet):
    # header do ethernet é 14 bytes
    if len(packet) < 14:
        return None
    eth_header = packet[:14]
    dst_mac, src_mac, proto = struct.unpack('!6s6sH', eth_header)
    return {
        "dst_mac": ':'.join('{:02x}'.format(b) for b in dst_mac),
        "src_mac": ':'.join('{:02x}'.format(b) for b in src_mac),
        "proto": proto,
        "payload": packet[14:]
    }


def analisar_cabecalho_ipv4(data):
    if len(data) < 20:
        return None
    # total_length pode estar em network order, unpack já tratou
    ver_ihl, tos, total_length, identification, flags_frag, ttl, proto, checksum, src, dst = struct.unpack('!BBHHHBBH4s4s', data[:20])
    version = ver_ihl >> 4
    ihl = ver_ihl & 0x0F
    header_length = ihl * 4
    try:
        src_ip = socket.inet_ntoa(src)
        dst_ip = socket.inet_ntoa(dst)
    except Exception:
        return None
    # evitar total_length inválido maior que o buffer
    payload = data[header_length:total_length] if (total_length <= len(data) and total_length >= header_length) else data[header_length:]
    raw = data[:total_length] if (total_length <= len(data) and total_length >= header_length) else data
    return {
        "version": version,
        "ihl": ihl,
        "tos": tos,
        "total_length": total_length,
        "id": identification,
        "flags_frag": flags_frag,
        "ttl": ttl,
        "proto": proto,
        "checksum": checksum,
        "src": src_ip,
        "dst": dst_ip,
        "header_length": header_length,
        "payload": payload,
        "raw": raw
    }


def analisar_cabecalho_ipv6(data):
    if len(data) < 40:
        return None
    v_tc_fl, payload_len, next_header, hop_limit = struct.unpack('!IHBB', data[:8])
    version = (v_tc_fl >> 28) & 0x0F
    try:
        src = socket.inet_ntop(socket.AF_INET6, data[8:24])
        dst = socket.inet_ntop(socket.AF_INET6, data[24:40])
    except Exception:
        return None
    payload = data[40:40+payload_len] if len(data) >= 40+payload_len else data[40:]
    raw = data[:40+payload_len] if len(data) >= 40+payload_len else data
    return {
        "version": version,
        "payload_len": payload_len,
        "next_header": next_header,
        "hop_limit": hop_limit,
        "src": src,
        "dst": dst,
        "payload": payload,
        "header_length": 40,
        "raw": raw
    }


def analisar_icmpv4(data):
    if len(data) < 4:
        return None
    icmp_type, code, checksum = struct.unpack('!BBH', data[:4])
    return {"type": icmp_type, "code": code, "checksum": checksum, "rest": data[4:]}


def analisar_cabecalho_tcp(data):
    if len(data) < 20:
        return None
    src_port, dst_port, seq, ack, offset_reserved_flags, window, checksum, urg_ptr = struct.unpack('!HHLLHHHH', data[:20])
    offset = (offset_reserved_flags >> 12) * 4
    flags = offset_reserved_flags & 0x01FF  # 9 bits of flags possibly
    payload = data[offset:]
    return {"src_port": src_port, "dst_port": dst_port, "seq": seq, "ack": ack, "offset": offset, "flags": flags, "window": window, "checksum": checksum, "urg_ptr": urg_ptr, "payload": payload}


def analisar_cabecalho_udp(data):
    if len(data) < 8:
        return None
    src_port, dst_port, length, checksum = struct.unpack('!HHHH', data[:8])
    payload = data[8:8 + (length - 8)] if (length - 8 <= len(data) - 8 and length >= 8) else data[8:]
    return {"src_port": src_port, "dst_port": dst_port, "length": length, "checksum": checksum, "payload": payload}

# descobrir qual dos protocolos de aplicacao é
def detectar_aplicacao(protocol_name, src_port, dst_port, payload):
    # HTTP: verifica as portas
    if protocol_name == "TCP":
        if src_port in HTTP_PORTS or dst_port in HTTP_PORTS:
            text = decodificar_segura(payload, maxlen=200)
            first_line = text.splitlines()[0] if text else ""
            # crude detection of request lines or response
            if any(first_line.startswith(m) for m in ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "HTTP/")):
                return "HTTP", first_line.strip()
            else:
                # still mark by port
                return "HTTP", f"port-based (src:{src_port},dst:{dst_port})"
    # DNS com TCP ou UDP
    if (protocol_name == "UDP" and (src_port in DNS_PORTS or dst_port in DNS_PORTS)) or (protocol_name == "TCP" and (src_port in DNS_PORTS or dst_port in DNS_PORTS)):
        try:
            if len(payload) >= 12:
                # transaction id
                tid = struct.unpack('!H', payload[:2])[0]
                # parse qname
                i = 12
                qname_parts = []
                while i < len(payload):
                    length = payload[i]
                    if length == 0:
                        break
                    i += 1
                    if i + length > len(payload):
                        break
                    qname_parts.append(payload[i:i+length].decode('ascii', errors='replace'))
                    i += length
                qname = ".".join(qname_parts) if qname_parts else ""
                return "DNS", f"tid={tid} qname={qname}"
        except Exception:
            return "DNS", "dns-pkt"
    # DHCP: UDP portas 67/68
    if protocol_name == "UDP" and (src_port in DHCP_PORTS or dst_port in DHCP_PORTS):
        info = "dhcp"
        try:
            if len(payload) >= 240:
                cookie = payload[236:240]
                if cookie == b'\x63\x82\x53\x63':
                    # find message type option 53
                    idx = 240
                    dhcp_type = None
                    while idx < len(payload):
                        opt = payload[idx]
                        if opt == 255:
                            break
                        if opt == 0:
                            idx += 1
                            continue
                        if idx + 1 >= len(payload):
                            break
                        optlen = payload[idx+1]
                        val = payload[idx+2:idx+2+optlen]
                        if opt == 53 and len(val) == 1:
                            dhcp_type = val[0]
                            break
                        idx += 2 + optlen
                    info = f"DHCP type={dhcp_type}" if dhcp_type is not None else "DHCP"
        except Exception:
            info = "DHCP"
        return "DHCP", info
    # NTP: UDP porta 123
    if protocol_name == "UDP" and (src_port in NTP_PORTS or dst_port in NTP_PORTS):
        if len(payload) >= 1:
            b = payload[0]
            leap = (b >> 6) & 0x03
            version = (b >> 3) & 0x07
            mode = b & 0x07
            return "NTP", f"ver={version} mode={mode} leap={leap}"
        return "NTP", "ntp-pkt"
    return None, None

# metodos pra gerar os logs
def registrar_internet(timestamp, proto_name, src_ip, dst_ip, proto_number, other_info, total_len):
    writer = escritores_csv[CSV_INTERNET]
    writer.writerow([timestamp, proto_name, src_ip, dst_ip, proto_number, other_info, total_len])
    persistir_csv(CSV_INTERNET)


def registrar_transporte(timestamp, proto_name, src_ip, src_port, dst_ip, dst_port, total_len):
    writer = escritores_csv[CSV_TRANSPORTE]
    writer.writerow([timestamp, proto_name, src_ip, src_port, dst_ip, dst_port, total_len])
    persistir_csv(CSV_TRANSPORTE)


def registrar_aplicacao(timestamp, proto_name, info):
    writer = escritores_csv[CSV_APLICACAO]
    writer.writerow([timestamp, proto_name, info])
    persistir_csv(CSV_APLICACAO)

# metodo pra atualizar as estatisticas dos clientes
def atualizar_estatisticas_cliente(tunnel_ip, remote_ip, remote_port, bytes_len):
    with trava_estatisticas_clientes:
        s = estatisticas_clientes[tunnel_ip]
        s["total_packets"] += 1
        s["total_bytes"] += bytes_len
        r = s["remotes"][remote_ip]
        r["packets"] += 1
        r["bytes"] += bytes_len
        if remote_port:
            r["ports"][remote_port] += 1

# processar um pacote IPv4 (extraido do TUN ou de um frame Ethernet)
def processar_ipv4(ip, bytes_len, timestamp):
    proto_num = ip["proto"]
    src_ip = ip["src"]
    dst_ip = ip["dst"]
    total_len = ip["total_length"] if ip.get("total_length") else bytes_len
    # registrar na camada de rede sempre como IPv4
    network_proto = "IPv4"
    other_info = ""
    # transporte/aplicacao: mantenha nomes conhecidos ou marque como Outro
    if proto_num == 1:
        network_proto = "ICMP"
        icmp = analisar_icmpv4(ip["payload"])
        other_info = f"type={icmp['type']} code={icmp['code']}" if icmp else ""
        with trava_contadores:
            contadores_proto["ICMP"] += 1
    elif proto_num == 6:
        with trava_contadores:
            contadores_proto["TCP"] += 1
        
    elif proto_num == 17:
        with trava_contadores:
            contadores_proto["UDP"] += 1
    else:
        # para protocolos não mapeados, use 'Outro' tanto no CSV quanto nos contadores
        with trava_contadores:
            contadores_proto["Outro"] += 1

    registrar_internet(timestamp, network_proto, src_ip, dst_ip, proto_num, other_info, total_len)

    # transporte layer
    if proto_num == 6:  # TCP
        tcp = analisar_cabecalho_tcp(ip["payload"])
        if not tcp:
            return
        src_port = tcp["src_port"]
        dst_port = tcp["dst_port"]
        tlen = len(ip["raw"])
        registrar_transporte(timestamp, "TCP", src_ip, src_port, dst_ip, dst_port, tlen)

        app, info = detectar_aplicacao("TCP", src_port, dst_port, tcp["payload"])
        if app:
            registrar_aplicacao(timestamp, app, info)
            with trava_contadores:
                contadores_proto[app] += 1

        if src_ip.startswith("172.31.66.") or dst_ip.startswith("172.31.66."):
            tunnel_ip = src_ip if src_ip.startswith("172.31.66.") else dst_ip
            remote_ip = dst_ip if tunnel_ip == src_ip else src_ip
            remote_port = dst_port if tunnel_ip == src_ip else src_port
            atualizar_estatisticas_cliente(tunnel_ip, remote_ip, remote_port, bytes_len)

    elif proto_num == 17:
        # se for UDP
        udp = analisar_cabecalho_udp(ip["payload"])
        if not udp:
            return
        src_port = udp["src_port"]
        dst_port = udp["dst_port"]
        tlen = len(ip["raw"])
        registrar_transporte(timestamp, "UDP", src_ip, src_port, dst_ip, dst_port, tlen)

        app, info = detectar_aplicacao("UDP", src_port, dst_port, udp["payload"])
        if app:
            registrar_aplicacao(timestamp, app, info)
            with trava_contadores:
                contadores_proto[app] += 1

        if src_ip.startswith("172.31.66.") or dst_ip.startswith("172.31.66."):
            tunnel_ip = src_ip if src_ip.startswith("172.31.66.") else dst_ip
            remote_ip = dst_ip if tunnel_ip == src_ip else src_ip
            remote_port = dst_port if tunnel_ip == src_ip else src_port
            atualizar_estatisticas_cliente(tunnel_ip, remote_ip, remote_port, bytes_len)

    elif proto_num == 1:  # ICMP
        if src_ip.startswith("172.31.66.") or dst_ip.startswith("172.31.66."):
            tunnel_ip = src_ip if src_ip.startswith("172.31.66.") else dst_ip
            remote_ip = dst_ip if tunnel_ip == src_ip else src_ip
            atualizar_estatisticas_cliente(tunnel_ip, remote_ip, None, bytes_len)

# processar um pacote IPv6
def processar_ipv6(ipv6, bytes_len, timestamp):
    proto_num = ipv6["next_header"]
    src_ip = ipv6["src"]
    dst_ip = ipv6["dst"]
    total_len = ipv6.get("payload_len", len(ipv6.get("raw", b"")))
    registrar_internet(timestamp, "IPv6", src_ip, dst_ip, proto_num, "", total_len)
    with trava_contadores:
        contadores_proto["IPv6"] += 1

    if proto_num == 6:
        tcp = analisar_cabecalho_tcp(ipv6["payload"])
        if tcp:
            registrar_transporte(timestamp, "TCP", src_ip, tcp["src_port"], dst_ip, tcp["dst_port"], total_len)
    elif proto_num == 17:
        udp = analisar_cabecalho_udp(ipv6["payload"])
        if udp:
            registrar_transporte(timestamp, "UDP", src_ip, udp["src_port"], dst_ip, udp["dst_port"], total_len)

# loop de captura de pacotes
def loop_captura(interface):
    global executando
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.bind((interface, 0))
    except PermissionError:
        print("Erro: precisa de permissões (root) para abrir raw socket. Rode com sudo.")
        sys.exit(1)
    except Exception as e:
        print(f"Erro abrindo socket raw: {e}")
        sys.exit(1)

    print(f"[+] Capturando na interface {interface} ... (pressione Ctrl+C para sair)")

    is_tun = interface.startswith("tun")

    while executando:
        try:
            packet, addr = s.recvfrom(65535)
        except InterruptedError:
            continue
        except Exception as e:
            if executando:
                print("Erro recvfrom:", e)
            break

        timestamp = iso_now()
        bytes_len = len(packet)

        # se for a interface tun0 , o pacote começa com IP direto, não tem enlace
        if is_tun:
            if bytes_len == 0:
                continue
            first_byte = packet[0]
            first_nibble = first_byte >> 4
            if first_nibble == 4:
                ip = analisar_cabecalho_ipv4(packet)
                if ip is None:
                    continue
                processar_ipv4(ip, bytes_len, timestamp)
                continue
            elif first_nibble == 6:
                ipv6 = analisar_cabecalho_ipv6(packet)
                if ipv6 is None:
                    continue
                processar_ipv6(ipv6, bytes_len, timestamp)
                continue
            else:
                # se não for reconhecido como IP, registrar como "other"
                with trava_contadores:
                    contadores_proto[f"TUN_UNKNOWN"] += 1
                registrar_internet(timestamp, "Outro", "-", "-", 0, "", bytes_len)
                continue

        # se for outra interface: parsear frame Ethernet
        eth = analisar_frame_ethernet(packet)
        if eth is None:
            continue

        # detecta se é ipv4 ou ipv6
        if eth["proto"] == 0x0800:
            # IPv4
            ip = analisar_cabecalho_ipv4(eth["payload"])
            if ip is None:
                continue
            processar_ipv4(ip, bytes_len, timestamp)

        elif eth["proto"] == 0x86DD:
            # caso seja ipv6
            ipv6 = analisar_cabecalho_ipv6(eth["payload"])
            if ipv6 is None:
                continue
            processar_ipv6(ipv6, bytes_len, timestamp)

        else:
            # se não for um ethertype tratado, marque como 'Outro'
            with trava_contadores:
                contadores_proto["Outro"] += 1
            registrar_internet(timestamp, "Outro", "-", "-", eth["proto"], "", bytes_len)

    try:
        s.close()
    except Exception:
        pass

# loop do console
def loop_interface(refresh_sec=1.0):
    global executando
    try:
        while executando:
            # limpa o terminal
            os.system('clear')
            # printa o contador atual
            print("Monitor de Tráfego - Interface (tempo real)")
            print(f"Time: {iso_now()}")
            print("-" * 60)
            with trava_contadores:
                print("Contadores gerais (top):")
                for proto, cnt in contadores_proto.most_common(20):
                    print(f"  {proto:12s} : {cnt}")
            print("-" * 60)
            print("Estatísticas por cliente (túnel 172.31.66.x):")
            with trava_estatisticas_clientes:
                for client_ip, s in list(estatisticas_clientes.items())[:20]:
                    print(f" {client_ip} -> pkts:{s['total_packets']:6d} bytes:{s['total_bytes']:8d} remotes:{len(s['remotes'])}")
                    # list top 3 remotos
                    top_rem = sorted(s['remotes'].items(), key=lambda kv: kv[1]['bytes'], reverse=True)[:3]
                    for rem_ip, info in top_rem:
                        top_ports = ", ".join(f"{p}:{c}" for p, c in info["ports"].most_common(3))
                        print(f"    {rem_ip:20s} pkts:{info['packets']:5d} bytes:{info['bytes']:7d} ports:[{top_ports}]")
            print("-" * 60)
            print(f"Logs CSV: {CSV_INTERNET}, {CSV_TRANSPORTE}, {CSV_APLICACAO}")
            print("Press Ctrl+C to stop and flush logs.")
            time.sleep(refresh_sec)
    except KeyboardInterrupt:
        executando = False
    except Exception as e:
        print("UI error:", e)
        executando = False

def stop(sig, frame):
    global executando
    print("\n[!] Sinal recebido, encerrando...")
    executando = False

def limpar():
    # fechar arquivos csv quando encerra a execucao
    for name, f in arquivos_csv.items():
        try:
            f.flush()
            os.fsync(f.fileno())
        except Exception:
            pass
        try:
            f.close()
        except Exception:
            pass
    print("[+] Arquivos CSV fechados.")

def main():
    global executando
    parser = argparse.ArgumentParser(description="Monitor de Tráfego de Rede - raw sockets")
    parser.add_argument("-i", "--interface", default=INTERFACE_PADRAO, help="Interface de captura (default: tun0)")
    args = parser.parse_args()

    garantir_cabecalhos_csv()

    # trap signals
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    # comeca a captura
    cap_thread = threading.Thread(target=loop_captura, args=(args.interface,), daemon=True)
    cap_thread.start()

    try:
        loop_interface()
    finally:
        executando = False
        cap_thread.join(timeout=2.0)
        limpar()
        print("[+] Monitor finalizado.")

if __name__ == "__main__":
    main()
