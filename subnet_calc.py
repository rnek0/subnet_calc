#!/usr/bin/env python3
# Calculo de subnet (con CIDR) / Ejercicios de entrenamiento (curso de Python Ofensivo hack4u.io)
# 08-04-2024 / rnek0
# Tool for check results : https://www.cidr.eu/en/calculator
import sys
import re
import ipaddress
from colores import *

class Banner:
    """Banner class se encarga de imprimir el banner y la ayuda."""
    title = """
                   __                      __      ________ 
       ____  ___  / /__      ______  _____/ /__   /  _/ __ \\
      / __ \/ _ \/ __/ | /| / / __ \/ ___/ //_/   / // / / /
     / / / /  __/ /_ | |/ |/ / /_/ / /  / ,<    _/ // /_/ / 
    /_/ /_/\___/\__/ |__/|__/\____/_/  /_/|_|  /___/_____/ 
    """
    
    @classmethod
    def display_banner(cls,ip=""):
        """Display banner app (cosmética)"""
        l = len(ip)
        spaces = f"  {'-'*(54 - l)}"
        ip_cidr = f"{ip}"
        print(f"{TUI.colorea(cls.title,Color.verde)}\n{spaces} {ip_cidr}\n")

    @classmethod
    def usage(cls, err=""):
        """Display help"""

        if err != "":
            alert = TUI.colorea(f" [!] ",Color.rojo)
            print(f"{alert}{err}")

        warning, ejemplo_ipv4 = TUI.colorea(f"[!]",Color.verde), TUI.colorea(f"192.168.1.1/24",Color.verde)
        ejemplo_ipv6 = TUI.colorea(f"2001:4b98:dc0:43:f816:3eff:fe10:e35e/64",Color.azul)
        print(f"\n {warning} USO :\n\t Entra el valor de la ip con notación CIDR.\n\t Ejemplos : \n\t  - {ejemplo_ipv4}\n\t  - {ejemplo_ipv6}\n")
        exit(1)

    @classmethod
    def display_line_result(cls, section, result):
        print(f"  {TUI.warning('[+]')} {section:<33}: {result}")
    
    @classmethod
    def exit_app(cls, err=""):
        cls.display_banner()
        cls.usage(err)


def check_ip_arg(arg_ip):
    """check_ip_arg verifica el parámetro de ip CIDR requerido"""
    ip_cidr = arg_ip

    if '/' in ip_cidr:
        if ':' in ip_cidr:
            ip = ip_cidr.split('/')[0] #print(f"IPv6: {ip_cidr}")
            mask_cidr = ip_cidr.split('/')[1] if int(ip_cidr.split('/')[1]) > 0 and int(ip_cidr.split('/')[1]) <= 128 else "no_cidr"
            if mask_cidr == "no_cidr":
                Banner.exit_app("La mask CIDR no esta dentro de los valores(1 a 128)")
        else:
            ip = ip_cidr.split('/')[0] #print(f"IPv4: {ip_cidr}")
            if CIDR.validate_ip_regex(ip):
                mask_cidr = ip_cidr.split('/')[1] if int(ip_cidr.split('/')[1]) > 0 and int(ip_cidr.split('/')[1]) <= 32 else "no_cidr"
                if mask_cidr == "no_cidr":
                    Banner.exit_app("La mask CIDR no esta dentro de los valores(1 a 32)")

            else:
                Banner.exit_app("La ip no es correcta.")
    else:
        Banner.exit_app("El formato CIDR se escribe con IP/Prefijo")

    Banner.display_banner(f"{ip}/{mask_cidr}") 

    return (ip,mask_cidr)   

class CIDR:
    def __init__(self, ip, prefix):
        # Creación de ip 'La factory' crea el objeto a partir de string ipv4 o ipv6
        self.__ip = ipaddress.ip_address(ip)
        self.__prefix = prefix
    

    @property
    def subred(self):
        ip_iface = ipaddress.ip_interface(f"{self.__ip}/{self.__prefix}")
        return ip_iface.network 

    @property
    def version(self):
        return self.__ip.version

    @classmethod
    def validate_ip_regex(cls,ip_address):
        """Check IPv4 Address. True if valid IPv4 ip."""
        if not bool(re.search(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", ip_address)):
           print(f"The IP address {ip_address} is not valid")
           return False

        bytes = ip_address.split(".")

        for ip_byte in bytes:
           if int(ip_byte) < 0 or int(ip_byte) > 255:
               print(f"The IP address {ip_address} is not valid")
               return False
        print(f"The IP address {ip_address} is valid")
        return True 



if __name__ == "__main__":
    if len(sys.argv) != 2:
        Banner.usage()
    
    # TODO : Faire la difference sur le calcul entre ipv4 et ipv6 ()

    ip,prefix = check_ip_arg( sys.argv[1] )

    cidr = CIDR(ip,prefix)

    # CIDR Range
    ip_version = TUI.colorea(f"{sys.argv[1]}",Color.verde)
    Banner.display_line_result("CIDR Range", ip_version)

    # Ip Versión
    ip_version = TUI.colorea(f"IPv{cidr.version}",Color.verde)
    Banner.display_line_result("Versión de la ip", ip_version)
    
    ipv4_network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False) # Definición de la red IP (strict=False lève l'interdiction de mettre a 1 )
    mascara = TUI.colorea(f"{ipv4_network.netmask}",Color.verde)

    # Máscara de red
    Banner.display_line_result("Netmask / Máscara de red", mascara)
    mascara_host = TUI.colorea(f"{ipv4_network.hostmask}",Color.verde)

    # Dirección de subred
    subred = TUI.colorea(f"{cidr.subred}",Color.verde)
    Banner.display_line_result("Dirección de subred", subred)
    
    Banner.display_line_result("Wildcard Bits / Máscara de host", mascara_host)

    mascara = TUI.colorea(f"{ipv4_network.num_addresses}",Color.verde)
    Banner.display_line_result("Total Host / Direcciones", mascara)
    print()