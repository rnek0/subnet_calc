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
      _____       __               __     ______      __    
     / ___/__  __/ /_  ____  ___  / /_   / ____/___ _/ /____
     \__ \/ / / / __ \/ __ \/ _ \/ __/  / /   / __ `/ / ___/
    ___/ / /_/ / /_/ / / / /  __/ /_   / /___/ /_/ / / /__  
   /____/\__,_/_.___/_/ /_/\___/\__/   \____/\__,_/_/\___/  """
    
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
        """Display line results"""
        warning = TUI.warning('[+]')
        print(f"  {warning} {section:<48}: {result}")
    
    @classmethod
    def exit_app(cls, err=""):
        """Exit on err"""
        cls.display_banner()
        cls.usage(err)


def check_ip_arg(arg_ip):
    """check_ip_arg verifica el bloque CIDR requerido. """
    ip_cidr = arg_ip

    if '/' in ip_cidr:
        if ':' in ip_cidr:
            ip = ip_cidr.split('/')[0] #print(f"IPv6: {ip_cidr}")
            mask_cidr = ip_cidr.split('/')[1] if int(ip_cidr.split('/')[1]) > 0 and int(ip_cidr.split('/')[1]) <= 128 else "no_cidr"
            if mask_cidr == "no_cidr":
                Banner.exit_app("La longitud de prefijo CIDR no esta dentro de los valores(1 a 128)")
        else:
            ip = ip_cidr.split('/')[0] #print(f"IPv4: {ip_cidr}")
            if CIDR.validate_ip_regex(ip):
                mask_cidr = ip_cidr.split('/')[1] if int(ip_cidr.split('/')[1]) > 0 and int(ip_cidr.split('/')[1]) <= 32 else "no_cidr"
                if mask_cidr == "no_cidr":
                    Banner.exit_app("La longitud de prefijo CIDR no esta dentro de los valores(1 a 32)")

            else:
                Banner.exit_app("La ip no es correcta.")
    else:
        Banner.exit_app("El formato de un bloque CIDR se escribe con IP/Prefijo")

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
           return False

        bytes = ip_address.split(".")

        for ip_byte in bytes:
           if int(ip_byte) < 0 or int(ip_byte) > 255:
               return False

        return True 



if __name__ == "__main__":
    if len(sys.argv) != 2:
        Banner.usage()
    
    # TODO : Faire la difference sur le calcul entre ipv4 et ipv6 ()

    ip,prefix = check_ip_arg( sys.argv[1] )
    cidr = CIDR(ip,prefix)

    # CIDR Range
    ip_version = TUI.colorea(f"{sys.argv[1]}",Color.azul)
    trad = "CIDR Range" + TUI.colorea(f"(Bloque CIDR)",Color.gris)
    Banner.display_line_result(trad, ip_version)

    # Ip Versión
    # ip_version = TUI.colorea(f"IPv{cidr.version}",Color.verde)
    # trad = TUI.colorea(f"(Bloque CIDR)",Color.gris)
    # Banner.display_line_result("Versión de la ip", ip_version)
    
    ipv4_network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False) # Definición de la red IP (strict=False lève l'interdiction de mettre a 1 )

    # Máscara de red
    mascara = TUI.colorea(f"{ipv4_network.netmask}",Color.azul)
    trad = "Subnet Mask " + TUI.colorea(f"(Máscara de subred)",Color.gris)
    Banner.display_line_result(trad, mascara)

    # Dirección de subred
    subred = TUI.colorea(f"{cidr.subred}",Color.azul)
    trad = f"Subnet address" + TUI.colorea(f"(Dirección subred)",Color.gris)
    Banner.display_line_result(f"{trad}", subred)
    
    # Wildcard Bits
    mascara_host = TUI.colorea(f"{ipv4_network.hostmask}",Color.azul)
    trad = f"Wildcard Bits" + TUI.colorea(f"(Máscara de host)",Color.gris)
    Banner.display_line_result(f"{trad}", mascara_host)

    #Total Hosts
    mascara = TUI.colorea(f"{ipv4_network.num_addresses}",Color.azul)
    trad = f"Total Hosts" + TUI.colorea(f"(Total Hosts)",Color.gris)
    Banner.display_line_result(f"{trad}", mascara)
    print()