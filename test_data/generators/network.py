"""Generate the synthetic TLS packet captures in test_data/network/, then verify them.

Run from the repository root (needs scapy and the network scanner): uv run python -m test_data.generators.network
No packets are transmitted.
"""

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, wrpcap
from scapy.layers.tls.all import (
    TLS, TLSClientHello, TLSServerHello, TLS_Ext_SupportedGroups,
    TLS_Ext_KeyShare_CH, TLS_Ext_KeyShare_SH, KeyShareEntry,
    TLS_Ext_SupportedVersion_CH, TLS_Ext_SupportedVersion_SH,
)

from test_data.generators.common import TEST_DATA, verify

FIXTURE = TEST_DATA / "network"
EXPECTED_COUNTS = {"CRITICAL": 3, "MEDIUM": 1, "SAFE": 1, "UNKNOWN": 1}


def tls_session(index, cipher, group=None, server=True):
    client, service = f'192.0.2.{index}', f'198.51.100.{index}'
    port = 50000 + index
    forward = Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / IP(src=client, dst=service)
    reverse = Ether(src='02:00:00:00:00:02', dst='02:00:00:00:00:01') / IP(src=service, dst=client)
    client_extensions = [TLS_Ext_SupportedGroups(groups=[group or 29])]
    server_extensions = []
    if group is not None:
        # Correct wire lengths; public key-share bytes are dummy test data.
        client_length, server_length = (1216, 1120) if group == 0x11ec else (32, 32)
        client_extensions += [TLS_Ext_SupportedVersion_CH(versions=[0x0304]),
                              TLS_Ext_KeyShare_CH(client_shares=[KeyShareEntry(group=group, key_exchange=b'\x01' * client_length)])]
        server_extensions = [TLS_Ext_SupportedVersion_SH(version=0x0304),
                             TLS_Ext_KeyShare_SH(server_share=KeyShareEntry(group=group, key_exchange=b'\x02' * server_length))]
    hello = TLS(version=0x0303, msg=[TLSClientHello(version=0x0303, gmt_unix_time=1700000000,
                random_bytes=bytes([index]) * 28, ciphers=[cipher], comp=[0], ext=client_extensions)])
    reply = TLS(version=0x0303, msg=[TLSServerHello(version=0x0303, gmt_unix_time=1700000001,
                random_bytes=bytes([index + 10]) * 28, cipher=cipher, comp=[0], ext=server_extensions)])
    packets = [forward / TCP(sport=port, dport=443, flags='S', seq=1000),
               reverse / TCP(sport=443, dport=port, flags='SA', seq=2000, ack=1001),
               forward / TCP(sport=port, dport=443, flags='A', seq=1001, ack=2001),
               forward / TCP(sport=port, dport=443, flags='PA', seq=1001, ack=2001) / hello]
    if server:
        packets.append(reverse / TCP(sport=443, dport=port, flags='PA', seq=2001, ack=1001 + len(bytes(hello))) / reply)
    return packets


def captures():
    return {
        'legacy_tls.pcap': tls_session(1, 0x002f) + tls_session(2, 0xc030) + tls_session(3, 0x1302, 29),
        'hybrid_safe_tls.pcap': tls_session(4, 0x1302, 0x11ec),
        'hybrid_aes128_tls.pcap': tls_session(5, 0x1301, 0x11ec),
        'clienthello_only.pcap': tls_session(6, 0x1302, 29, server=False),
        'non_tls.pcap': [Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') /
                         IP(src='192.0.2.100', dst='198.51.100.53') / UDP(sport=53000, dport=53) /
                         DNS(id=1, rd=1, qd=DNSQR(qname='demo.example.test'))],
    }


def generate(target=FIXTURE):
    target.mkdir(parents=True, exist_ok=True)
    for name, packets in captures().items():
        for index, packet in enumerate(packets):
            packet.time = 1700000000 + index / 10
        wrpcap(str(target / name), packets)


if __name__ == "__main__":
    generate()
    verify("network", FIXTURE, EXPECTED_COUNTS)
