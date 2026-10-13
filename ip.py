from iputils import *
from dataclasses import dataclass

# IP : CIDR
# IP é o identificador consiste em 32 bits: 192.168.1.50  
# CIDR: definir um intervalo (ou bloco) de endereços IP.  
    # IP de referência + '/'  + um número para dizer o tamanho da rede em bits. 
        # 192.168.1.0/24
        # (indo do 192.168.1.0 até o 192.168.1.255).
# Esse CIDR representa todos os IPs que começam com 192.168.1. 

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela_encaminhamento: dict[str, str] = {}

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            self.enlace.enviar(datagrama, next_hop)


    def isInCIDR(dest_addr, cidr):
        # Separando e pegando os tamanho da rede
        network_addr, prefix = cidr.split('/')
        network_size = int(prefix)

        # IP para bytes
        dest = int.from_bytes(str2addr(dest_addr), 'big')
        network = int.from_bytes(str2addr(network_addr), 'big')

        # Criando máscara de subrede
        mask = (0xFFFFFFFF << (32 - network_size)) & 0xFFFFFFFF

        return (dest & mask) == (network & mask)


    def _next_hop(self, dest_addr):
        for cidr in self.tabela_encaminhamento:
            if isInCIDR(dest_addr, cidr):
                return self.tabela_encaminhamento[cidr].next_hop

        return None

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        self.tabela_encaminhamento = tabela
        pass

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.
        self.enlace.enviar(datagrama, next_hop)
