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

@dataclass
class ICMPHeader:
    checksum: int
    type = 11 # Time Exceeded Code,
    code = 0 # Time to live (TTL) expired in transit,
    rest_of_header: bytes = b'\x00\x00\x00\x00' # 4 bytes zerados fixos


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
        self.tabela_encaminhamento: list[tuple[str, str]] = []


    @staticmethod
    def generate_icmp_time_out_message(datagrama):
        ihl = (datagrama[0] & 0x0F) * 4
        icmp_payload = datagrama[:ihl + 8]

        header = ICMPHeader(0)

        icmp_header = struct.pack(
            '!BBH4s',
            header.type,
            header.code,
            0,
            header.rest_of_header
        )

        icmp_message = icmp_header + icmp_payload
        checksum = calc_checksum(icmp_message)

        icmp_header = struct.pack(
            '!BBH4s',
            header.type,
            header.code,
            checksum,
            header.rest_of_header
        )

        return icmp_header + icmp_payload

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)

        print("Destino:", dst_addr)
        print("Meu endereço:", self.meu_endereco)
        print("TTL:", ttl)
        print("Tabela:", self.tabela_encaminhamento)

        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # Descarta o pacote
            if ttl <= 1:
                next_hop = self._next_hop(src_addr)
                if next_hop is None:
                    return
                icmp_payload = self.generate_icmp_time_out_message(datagrama)
                icmp_datagrama = self._montar_datagrama(
                    icmp_payload,
                    protocol=IPPROTO_ICMP,
                    dest_addr=src_addr,
                )
                self.enlace.enviar(icmp_datagrama, next_hop)
                return
            # atua como roteador
            next_hop = self._next_hop(dst_addr)

            # Decrementa o TTL
            ttl -= 1

            # Modifica o datagrama
            datagrama = bytearray(datagrama)
            datagrama[8] = ttl

            # Zera checksum
            datagrama[10:12] = b'\x00\x00'

            # Calcula checksum do cabeçalho
            ihl = (datagrama[0] & 0x0F) * 4
            checksum = calc_checksum(bytes(datagrama[:ihl]))

            # Insere checksum atualizado
            datagrama[10:12] = struct.pack('!H', checksum)

            self.enlace.enviar(bytes(datagrama), next_hop)

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



    def longest_prefix_match(
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

        best_candidate = self.longest_prefix_match(possible_candidates)

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
        self.tabela_encaminhamento = tabela
        pass

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback


    def _montar_datagrama(self, payload: bytes, protocol: int, dest_addr: str) -> bytes:
        header = IPV4_Header(
            src_addr=self.meu_endereco,
            dst_addr=dest_addr,
            protocol=protocol,
        )

        total_size = 20 + len(payload)

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

        return cabecalho + payload

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        if next_hop is None:
            return

        datagrama = self._montar_datagrama(segmento, IPPROTO_TCP, dest_addr)

        self.enlace.enviar(datagrama, next_hop)
