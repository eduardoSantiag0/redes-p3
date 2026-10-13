from iputils import *
import struct
from dataclasses import dataclass

# IP : CIDR
# IP é o identificador consiste em 32 bits: 192.168.1.50  
# CIDR: definir um intervalo (ou bloco) de endereços IP.  
    # IP de referência + '/'  + um número para dizer o tamanho da rede em bits. 
        # 192.168.1.0/24
        # (indo do 192.168.1.0 até o 192.168.1.255).
# Esse CIDR representa todos os IPs que começam com 192.168.1. 

@dataclass
class IPV4_Header:
    src_addr: str
    dst_addr: str
    ttl: int = 64

    ihl: int = 5  # tamanho
    dscp: int = 0  # prioridade
    total_size: int = 20

    flags: int = 0
    frag_offset: int = 0  # (Deslocamento se houver fragmentação)

    protocol: int = 6  # (Código 6 fixo para o protocolo TCP)
    checksum: int = 0


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
        self.tabela_encaminhamento: list[tuple[str, str]] = [
            ('172.30.192.1/32', '172.30.192.1')
        ]
    


    
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

    @staticmethod
    def isInCIDR(dest_addr: str, cidr: str) -> bool:
        # Separando e pegando os tamanho da rede
        network_addr, prefix = cidr.split('/')
        network_size: int = int(prefix)

        # IP para bytes
        dest: int = int.from_bytes(str2addr(dest_addr), 'big')
        network: int = int.from_bytes(str2addr(network_addr), 'big')
        
        # Criando máscara de subrede
        mask = (0xFFFFFFFF << (32 - network_size)) & 0xFFFFFFFF

        return (dest & mask) == (network & mask)



    def longest_prefix(
            self,
            candidates: list[tuple[str, str]]
    ) -> tuple[str, str] | None:
        if not candidates:
            return None

        best_candidate = candidates[0]

        for cidr, next_hop in candidates:
            prefix = int(cidr.split('/')[1])

            best_prefix = int(best_candidate[0].split('/')[1])

            if prefix > best_prefix:
                best_candidate = (cidr, next_hop)

        return best_candidate

    def _next_hop(self, dest_addr: str) -> str | None:
        possible_candidates: list[tuple[str, str]] = []

        for cidr, next_hop in self.tabela_encaminhamento:
            if self.isInCIDR(dest_addr, cidr):
                possible_candidates.append((cidr, next_hop))

        best_candidate = self.longest_prefix(possible_candidates)

        if best_candidate is not None:
            return best_candidate[1]

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


#TODO: Monte um datagrama IP que contenha como payload o segmento TCP fornecido.

    def enviar(self, segmento, dest_addr):

        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        if next_hop is None:
            return

        header = IPV4_Header(
            src_addr=self.meu_endereco,
            dst_addr=dest_addr
        )

        total_size = 20 + len(segmento)

        version_ihl = (4 << 4) | header.ihl
        dscp_ecn = header.dscp << 2
        flags_fragment = (header.flags << 13) | header.frag_offset

        identification = 0

        campos_sem_checksum = (
            version_ihl,
            dscp_ecn,
            total_size,
            identification,
            flags_fragment,
            header.ttl,
            header.protocol,
        )

        cabecalho_sem_checksum = struct.pack(
            '!BBHHHBBH4s4s',
            *campos_sem_checksum,
            0,
            str2addr(header.src_addr),
            str2addr(header.dst_addr)
        )

        checksum = calc_checksum(cabecalho_sem_checksum)

        cabecalho = struct.pack(
            '!BBHHHBBH4s4s',
            *campos_sem_checksum,
            checksum,
            str2addr(header.src_addr),
            str2addr(header.dst_addr)
        )

        datagrama = cabecalho + segmento



        self.enlace.enviar(datagrama, next_hop)
