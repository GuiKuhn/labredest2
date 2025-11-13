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
from collections import Counter

INTERFACE_PADRAO = "wlo1"
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
                "ip_origem",
                "ip_destino",
                "tamanho_total_bytes"
            ])
            if FORCAR_FLUSH:
                f.flush()
                os.fsync(f.fileno())
        arquivos_csv[CSV_APLICACAO] = f
        escritores_csv[CSV_APLICACAO] = writer


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
    ver_ihl, tos, total_length, identification, flags_frag, ttl, proto, checksum, src, dst = struct.unpack('!BBHHHBBH4s4s', data[:20])
    version = ver_ihl >> 4
    ihl = ver_ihl & 0x0F
    header_length = ihl * 4
    src_ip = socket.inet_ntoa(src)
    dst_ip = socket.inet_ntoa(dst)
    payload = data[header_length:total_length] if total_length <= len(data) else data[header_length:]
    return {
        "version": version,
        "proto": proto,
        "src": src_ip,
        "dst": dst_ip,
        "total_length": total_length,
        "payload": payload,
        "raw": data[:total_length] if total_length <= len(data) else data
    }


def analisar_cabecalho_ipv6(data):
    if len(data) < 40:
        return None
    v_tc_fl, payload_len, next_header, hop_limit = struct.unpack('!IHBB', data[:8])
    version = (v_tc_fl >> 28) & 0x0F
    src = socket.inet_ntop(socket.AF_INET6, data[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, data[24:40])
    payload = data[40:40+payload_len] if len(data) >= 40+payload_len else data[40:]
    return {
        "version": version,
        "next_header": next_header,
        "src": src,
        "dst": dst,
        "payload_len": payload_len,
        "payload": payload,
        "raw": data
    }


def analisar_icmpv4(data):
    if len(data) < 4:
        return None
    icmp_type, code, checksum = struct.unpack('!BBH', data[:4])
    return {"type": icmp_type, "code": code, "checksum": checksum}


def analisar_cabecalho_tcp(data):
    if len(data) < 20:
        return None
    src_port, dst_port, seq, ack, offset_reserved_flags, window, checksum, urg_ptr = struct.unpack('!HHLLHHHH', data[:20])
    offset = (offset_reserved_flags >> 12) * 4
    payload = data[offset:]
    return {"src_port": src_port, "dst_port": dst_port, "payload": payload}


def analisar_cabecalho_udp(data):
    if len(data) < 8:
        return None
    src_port, dst_port, length, checksum = struct.unpack('!HHHH', data[:8])
    payload = data[8:8 + (length - 8)] if length - 8 <= len(data) - 8 else data[8:]
    return {"src_port": src_port, "dst_port": dst_port, "length": length, "payload": payload}


def detectar_aplicacao(protocol_name, src_port, dst_port):
    if protocol_name == "TCP" and (src_port in HTTP_PORTS or dst_port in HTTP_PORTS):
        return "HTTP"
    if src_port in DNS_PORTS or dst_port in DNS_PORTS:
        return "DNS"
    if src_port in DHCP_PORTS or dst_port in DHCP_PORTS:
        return "DHCP"
    if src_port in NTP_PORTS or dst_port in NTP_PORTS:
        return "NTP"
    return None


def registrar_internet(timestamp, proto_name, src_ip, dst_ip, proto_number, total_len):
    writer = escritores_csv[CSV_INTERNET]
    writer.writerow([timestamp, proto_name, src_ip, dst_ip, proto_number, total_len])
    persistir_csv(CSV_INTERNET)


def registrar_transporte(timestamp, proto_name, src_ip, src_port, dst_ip, dst_port, total_len):
    writer = escritores_csv[CSV_TRANSPORTE]
    writer.writerow([timestamp, proto_name, src_ip, src_port, dst_ip, dst_port, total_len])
    persistir_csv(CSV_TRANSPORTE)


def registrar_aplicacao(timestamp, proto_name, src_ip, dst_ip, total_len):
    writer = escritores_csv[CSV_APLICACAO]
    writer.writerow([timestamp, proto_name, src_ip, dst_ip, total_len])
    persistir_csv(CSV_APLICACAO)


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
        eth = analisar_frame_ethernet(packet)
        if eth is None:
            continue

        if eth["proto"] == 0x0800:  # IPv4
            ip = analisar_cabecalho_ipv4(eth["payload"])
            if ip is None:
                continue
            proto_num = ip["proto"]
            src_ip = ip["src"]
            dst_ip = ip["dst"]
            total_len = ip["total_length"]


            # rótulo para a camada de rede (internet.csv): registrar apenas IPv4 ou ICMP
            if proto_num == 1:
                net_proto = "ICMP"
            else:
                net_proto = "IPv4"

            # rótulo para uso em contadores/logs (transporte quando aplicável)
            if proto_num == 1:
                trans_proto = "ICMP"
            elif proto_num == 6:
                trans_proto = "TCP"
            elif proto_num == 17:
                trans_proto = "UDP"
            else:
                trans_proto = f"IPv4_proto_{proto_num}"

            registrar_internet(timestamp, net_proto, src_ip, dst_ip, proto_num, total_len)

            if proto_num == 6:  # TCP
                tcp = analisar_cabecalho_tcp(ip["payload"])
                if not tcp:
                    continue
                registrar_transporte(timestamp, "TCP", src_ip, tcp["src_port"], dst_ip, tcp["dst_port"], total_len)
                app = detectar_aplicacao("TCP", tcp["src_port"], tcp["dst_port"])
                if app:
                    registrar_aplicacao(timestamp, app, src_ip, dst_ip, total_len)
                    with trava_contadores:
                        contadores_proto[app] += 1

            elif proto_num == 17:  # UDP
                udp = analisar_cabecalho_udp(ip["payload"])
                if not udp:
                    continue
                registrar_transporte(timestamp, "UDP", src_ip, udp["src_port"], dst_ip, udp["dst_port"], total_len)
                app = detectar_aplicacao("UDP", udp["src_port"], udp["dst_port"])
                if app:
                    registrar_aplicacao(timestamp, app, src_ip, dst_ip, total_len)
                    with trava_contadores:
                        contadores_proto[app] += 1

            with trava_contadores:
                contadores_proto[trans_proto] += 1

        elif eth["proto"] == 0x86DD:  # IPv6
            ipv6 = analisar_cabecalho_ipv6(eth["payload"])
            if ipv6 is None:
                continue
            proto_num = ipv6["next_header"]
            registrar_internet(timestamp, "IPv6", ipv6["src"], ipv6["dst"], proto_num, ipv6["payload_len"])
            with trava_contadores:
                contadores_proto["IPv6"] += 1

        else:
            with trava_contadores:
                contadores_proto[f"ETH_{hex(eth['proto'])}"] += 1
            registrar_internet(timestamp, "other", "-", "-", eth["proto"], bytes_len)

    try:
        s.close()
    except Exception:
        pass


def loop_interface(refresh_sec=1.0):
    global executando
    try:
        while executando:
            os.system('clear')
            print("Monitor de Tráfego - Interface (tempo real)")
            print(f"Time: {iso_now()}")
            print("-" * 60)
            with trava_contadores:
                print("Contadores gerais (top):")
                for proto, cnt in contadores_proto.most_common(20):
                    print(f"  {proto:12s} : {cnt}")
            print("-" * 60)
            print(f"Logs CSV: {CSV_INTERNET}, {CSV_TRANSPORTE}, {CSV_APLICACAO}")
            print("Press Ctrl+C to stop and flush logs.")
            time.sleep(refresh_sec)
    except KeyboardInterrupt:
        executando = False
    except Exception as e:
        print("UI error:", e)
        executando = False


def stop(signum, frame):
    global executando
    print("\n[!] Sinal recebido, encerrando...")
    executando = False


def limpar():
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
    parser.add_argument("interface", nargs="?", default=INTERFACE_PADRAO, help="Interface de captura (ex: enp4s0, wlan0)")
    args = parser.parse_args()

    garantir_cabecalhos_csv()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

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
