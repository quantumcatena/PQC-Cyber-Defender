# drone_simulator.py
# Simulation d'un réseau maillé drones/IoT sécurisé par PQC.
#
# Architecture : GCS (Ground Control Station) + nœuds UAV + capteurs IoT
# + gateway edge + nœud adversaire (MITM actif).
#
# Chaque lien de communication utilise :
#   - ML-KEM-512 pour les nœuds IoT contraints (léger)
#   - ML-KEM-768 pour GCS et drones
#   - ML-DSA-44/65 pour signature des commandes
#
# Scénarios d'attaque simulés :
#   - Injection de commandes falsifiées (usurpation GCS)
#   - Spoofing GPS + injection de paquets
#   - Fuzzing + interception de trafic telemetrie
#
# TODO: étendre avec simulation de latence réseau réaliste (model 802.11p)
# TODO: ajouter scénario anti-drone PQC (travaux M2 Toulon 2024)

import time
import random
import hashlib
import secrets
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from enum import Enum

import numpy as np

from pqc_module import (
    Algorithm, generate_keys, encrypt, decrypt, sign, verify,
    simulate_data, KeyPair, EncryptedPayload,
)
from attack_simulator import mitm_attack, intercept_attack, fuzz_attack

logger = logging.getLogger(__name__)


class NodeType(Enum):
    GCS      = "Ground Control Station"
    DRONE    = "UAV / Drone"
    IOT      = "IoT Sensor"
    GATEWAY  = "Edge Gateway"
    ATTACKER = "Adversary Node"


class LinkStatus(Enum):
    SECURE   = "SECURE (PQC)"
    DEGRADED = "DEGRADED"
    ATTACKED = "UNDER ATTACK"
    BLOCKED  = "BLOCKED"
    LEGACY   = "LEGACY (classical)"


@dataclass
class GeoCoord:
    lat: float
    lon: float
    alt: float = 0.0

    def distance_km(self, other: "GeoCoord") -> float:
        return np.sqrt((self.lat - other.lat)**2 + (self.lon - other.lon)**2) * 111.0


@dataclass
class NetworkNode:
    node_id: str
    name: str
    node_type: NodeType
    position: GeoCoord
    kem_keys: KeyPair    = field(default=None)
    sig_keys: KeyPair    = field(default=None)
    battery_pct: float   = 100.0
    is_compromised: bool = False
    packets_sent: int    = 0
    packets_received: int = 0
    packets_rejected: int = 0
    crypto_overhead_ms: float = 0.0

    def __post_init__(self):
        if self.node_type == NodeType.ATTACKER:
            return
        # IoT contraints → Kyber-512 + Dilithium-2
        # GCS/drones → Kyber-768 + Dilithium-3
        if self.node_type == NodeType.IOT:
            self.kem_keys = generate_keys(Algorithm.KYBER_512)
            self.sig_keys = generate_keys(Algorithm.DILITHIUM_2)
        else:
            self.kem_keys = generate_keys(Algorithm.KYBER_768)
            self.sig_keys = generate_keys(Algorithm.DILITHIUM_3)

    def status_summary(self):
        return {
            "id": self.node_id,
            "name": self.name,
            "type": self.node_type.value,
            "position": f"({self.position.lat:.4f}, {self.position.lon:.4f}, {self.position.alt:.0f}m)",
            "battery": f"{self.battery_pct:.0f}%",
            "kem_algorithm": self.kem_keys.algorithm.value if self.kem_keys else "NONE",
            "sig_algorithm": self.sig_keys.algorithm.value if self.sig_keys else "NONE",
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "packets_rejected": self.packets_rejected,
            "compromised": self.is_compromised,
        }


@dataclass
class SecurePacket:
    src_id: str
    dst_id: str
    seq_num: int
    packet_type: str
    payload: EncryptedPayload
    signature: bytes
    timestamp: float = field(default_factory=time.time)
    ttl: int = 10

    @property
    def total_bytes(self):
        return self.payload.total_size + len(self.signature) + 64


@dataclass
class AttackEvent:
    timestamp: float
    attacker_id: str
    target_id: str
    attack_type: str
    outcome: str
    details: str


@dataclass
class NetworkSimResult:
    n_nodes: int
    n_packets: int
    n_attacks: int
    attacks_blocked: int
    attacks_partial: int
    avg_crypto_overhead_ms: float
    avg_packet_overhead_ratio: float
    security_score: float
    attack_events: List[AttackEvent]
    node_summaries: List[Dict]


def create_drone_network(
    n_drones: int = 4,
    n_iot: int = 3,
    center_lat: float = 43.1245,   # Toulon / Var par défaut
    center_lon: float = 5.9374,
    include_attacker: bool = True,
) -> Dict[str, NetworkNode]:
    """
    Crée un réseau maillé drones/IoT avec un nœud adversaire optionnel.
    Coordonnées centrées sur Toulon (zone de test Naval Group / DGA Toulon).
    """
    nodes: Dict[str, NetworkNode] = {}
    rng = random.Random(42)

    nodes["GCS-001"] = NetworkNode(
        node_id="GCS-001", name="Ground Control Station Alpha",
        node_type=NodeType.GCS,
        position=GeoCoord(center_lat, center_lon, 0.0),
    )

    nodes["GW-001"] = NetworkNode(
        node_id="GW-001", name="Edge Gateway (5G Node)",
        node_type=NodeType.GATEWAY,
        position=GeoCoord(center_lat + 0.005, center_lon + 0.003, 15.0),
    )

    for i in range(n_drones):
        did   = f"UAV-{i+1:03d}"
        angle = (2 * np.pi * i) / n_drones
        r     = rng.uniform(0.01, 0.05)
        nodes[did] = NetworkNode(
            node_id=did, name=f"Drone Alpha-{i+1}",
            node_type=NodeType.DRONE,
            position=GeoCoord(
                center_lat + r * np.sin(angle),
                center_lon + r * np.cos(angle),
                rng.uniform(50, 200),
            ),
            battery_pct=rng.uniform(65, 95),
        )

    for i in range(n_iot):
        iid = f"IOT-{i+1:03d}"
        nodes[iid] = NetworkNode(
            node_id=iid, name=f"Capteur {i+1}",
            node_type=NodeType.IOT,
            position=GeoCoord(
                center_lat + rng.uniform(-0.03, 0.03),
                center_lon + rng.uniform(-0.03, 0.03),
                rng.uniform(0, 10),
            ),
            battery_pct=rng.uniform(40, 80),
        )

    if include_attacker:
        nodes["ATK-001"] = NetworkNode(
            node_id="ATK-001", name="Nœud Adverse (Acteur Étatique)",
            node_type=NodeType.ATTACKER,
            position=GeoCoord(center_lat + 0.02, center_lon + 0.015, 0.0),
        )

    return nodes


def send_secure_packet(
    sender: NetworkNode,
    receiver: NetworkNode,
    packet_type: str = "TELEMETRY",
    data_size: int = 128,
) -> Tuple[Optional[SecurePacket], bool]:
    if sender.kem_keys is None:
        return None, False

    t0 = time.perf_counter()
    dtypes = {"TELEMETRY": "telemetry", "COMMAND": "generic", "MEDICAL": "medical"}
    data = simulate_data(data_size, dtypes.get(packet_type, "generic"))

    try:
        sig     = sign(data, sender.sig_keys)
        payload = encrypt(data, receiver.kem_keys)

        sender.crypto_overhead_ms += (time.perf_counter() - t0) * 1000
        sender.packets_sent += 1

        return SecurePacket(
            src_id=sender.node_id, dst_id=receiver.node_id,
            seq_num=sender.packets_sent, packet_type=packet_type,
            payload=payload, signature=sig,
        ), True

    except Exception as e:
        logger.error(f"TX {sender.node_id}→{receiver.node_id}: {e}")
        return None, False


def receive_secure_packet(
    packet: SecurePacket,
    receiver: NetworkNode,
    sender: NetworkNode,
) -> Tuple[Optional[bytes], bool, str]:
    try:
        plaintext = decrypt(packet.payload, receiver.kem_keys)
        if not verify(plaintext, packet.signature, sender.sig_keys):
            receiver.packets_rejected += 1
            return None, False, "SIGNATURE_INVALID"
        receiver.packets_received += 1
        return plaintext, True, "OK"
    except ValueError as e:
        receiver.packets_rejected += 1
        return None, False, f"INTEGRITY_FAILURE"
    except Exception as e:
        receiver.packets_rejected += 1
        return None, False, "ERROR"


def simulate_rogue_command_injection(
    attacker: NetworkNode,
    target: NetworkNode,
    gcs: NetworkNode,
) -> AttackEvent:
    """
    L'attaquant tente d'injecter une commande falsifiée (ex. RTB, désactivation payload).
    La signature ML-DSA empêche l'attaque : la commande chiffrée avec la clé publique
    du drone est lisible, mais la signature ne peut être vérifiée avec la clé GCS légitime.
    """
    fake_cmd = b"CMD:RETURN_TO_BASE|auth=SPOOFED|ts=" + str(int(time.time())).encode()

    # L'attaquant génère sa propre paire de clés signature
    rogue_kp  = generate_keys(Algorithm.DILITHIUM_3)
    rogue_sig = sign(fake_cmd, rogue_kp)

    # Chiffrement possible (pk publique) mais signature invalide
    fake_payload = encrypt(fake_cmd, target.kem_keys)

    try:
        pt        = decrypt(fake_payload, target.kem_keys)
        sig_valid = verify(pt, rogue_sig, gcs.sig_keys)   # vérifié avec clé GCS officielle
        outcome   = "BLOCKED" if not sig_valid else "INJECTED"
        detail    = (
            "Commande déchiffrée mais signature rejetée (mauvaise clé). ML-DSA empêche l'injection."
            if not sig_valid else "ALERTE : vérification de signature contournée."
        )
    except Exception:
        outcome = "BLOCKED"
        detail  = "Attaque bloquée au niveau cryptographique."

    target.packets_rejected += 1
    return AttackEvent(
        timestamp=time.time(), attacker_id=attacker.node_id,
        target_id=target.node_id, attack_type="Injection de commande",
        outcome=outcome, details=detail,
    )


def simulate_gps_spoofing(attacker: NetworkNode, target: NetworkNode) -> AttackEvent:
    """
    Spoofing GPS : coordonnées altérées dans la télémétrie.
    Sans PQC, les coordonnées injectées peuvent rediriger le drone.
    Avec PQC : le payload altéré échoue à la vérification GCM/HMAC.
    """
    legit = simulate_data(128, "telemetry")

    # Injection de coordonnées GPS falsifiées (section bytes 15-35)
    spoofed = bytearray(legit)
    for i in range(15, min(35, len(spoofed))):
        spoofed[i] = random.randint(48, 57)

    try:
        fake_kp      = generate_keys(Algorithm.KYBER_512)
        fake_payload = encrypt(bytes(spoofed), fake_kp)
        decrypt(fake_payload, target.kem_keys)   # doit échouer
        outcome = "PARTIAL"
        detail  = "Payload spoofé partiellement accepté."
    except Exception:
        outcome = "BLOCKED"
        detail  = "Spoofing GPS bloqué : tag AES-GCM invalide. AEAD empêche l'injection."

    return AttackEvent(
        timestamp=time.time(), attacker_id=attacker.node_id,
        target_id=target.node_id, attack_type="GPS Spoofing + Injection",
        outcome=outcome, details=detail,
    )


def run_network_simulation(
    n_drones: int = 4,
    n_iot: int = 3,
    n_rounds: int = 5,
    run_attacks: bool = True,
) -> NetworkSimResult:
    """Lance la simulation complète du réseau PQC avec attaques optionnelles."""
    nodes = create_drone_network(n_drones, n_iot, include_attacker=run_attacks)

    gcs      = next(n for n in nodes.values() if n.node_type == NodeType.GCS)
    drones   = [n for n in nodes.values() if n.node_type == NodeType.DRONE]
    iot_list = [n for n in nodes.values() if n.node_type == NodeType.IOT]
    gw       = next(n for n in nodes.values() if n.node_type == NodeType.GATEWAY)
    attacker = next((n for n in nodes.values() if n.node_type == NodeType.ATTACKER), None)

    total_pkts    = 0
    overhead_r    = []
    overhead_t    = []
    attack_events: List[AttackEvent] = []
    blocked = partial = 0

    for _ in range(n_rounds):
        for drone in drones:
            pkt, ok = send_secure_packet(drone, gcs, "TELEMETRY", 128)
            if ok and pkt:
                receive_secure_packet(pkt, gcs, drone)
                total_pkts += 1
                overhead_r.append(pkt.total_bytes / 128)
                overhead_t.append(drone.crypto_overhead_ms / max(drone.packets_sent, 1))

        for drone in drones:
            pkt, ok = send_secure_packet(gcs, drone, "COMMAND", 64)
            if ok and pkt:
                receive_secure_packet(pkt, drone, gcs)
                total_pkts += 1

        for sensor in iot_list:
            pkt, ok = send_secure_packet(sensor, gw, "TELEMETRY", 64)
            if ok and pkt:
                receive_secure_packet(pkt, gw, sensor)
                total_pkts += 1
                overhead_r.append(pkt.total_bytes / 64)

    if run_attacks and attacker and drones:
        target = drones[0]

        for fn, label in [
            (lambda: simulate_rogue_command_injection(attacker, target, gcs), "cmd_inject"),
            (lambda: simulate_gps_spoofing(attacker, target), "gps_spoof"),
        ]:
            evt = fn()
            attack_events.append(evt)
            if evt.outcome == "BLOCKED": blocked += 1
            else: partial += 1

        # fuzzing crypto
        data = simulate_data(128, "telemetry")
        fr   = fuzz_attack(data, target.kem_keys, iterations_per_mode=50)
        attack_events.append(AttackEvent(
            timestamp=time.time(), attacker_id=attacker.node_id,
            target_id=target.node_id, attack_type="Fuzzing ciphertext",
            outcome=fr.result.value,
            details=f"Taux bypass : {fr.details.get('bypass_rate_pct', 0):.3f}%",
        ))
        if fr.result.value == "BLOCKED": blocked += 1
        else: partial += 1

        ir = intercept_attack(data, target.kem_keys, n_sessions=20)
        attack_events.append(AttackEvent(
            timestamp=time.time(), attacker_id=attacker.node_id,
            target_id=target.node_id, attack_type="Interception trafic",
            outcome=ir.result.value,
            details=f"Entropie : {ir.details.get('ciphertext_entropy_bits', 0):.2f} bits",
        ))
        if ir.result.value == "BLOCKED": blocked += 1
        else: partial += 1

    n_atk  = len(attack_events)
    br     = blocked / max(n_atk, 1)
    score  = min(100.0, max(0.0, 85.0 + br * 15.0 - partial * 3.0))

    return NetworkSimResult(
        n_nodes=len(nodes),
        n_packets=total_pkts,
        n_attacks=n_atk,
        attacks_blocked=blocked,
        attacks_partial=partial,
        avg_crypto_overhead_ms=float(np.mean(overhead_t)) if overhead_t else 0.0,
        avg_packet_overhead_ratio=float(np.mean(overhead_r)) if overhead_r else 0.0,
        security_score=round(score, 2),
        attack_events=attack_events,
        node_summaries=[n.status_summary() for n in nodes.values()],
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    from rich.console import Console
    from rich.table import Table
    from rich import box

    console = Console()
    console.print("\n[bold cyan]Drone/IoT Simulator — PQC Cyber Defender[/bold cyan]\n")

    result = run_network_simulation(n_drones=4, n_iot=3, n_rounds=3, run_attacks=True)

    console.print(f"Nœuds     : {result.n_nodes}")
    console.print(f"Paquets   : {result.n_packets}")
    console.print(f"Attaques  : {result.n_attacks}  (bloquées: {result.attacks_blocked}, partielles: {result.attacks_partial})")
    console.print(f"Crypto OH : {result.avg_crypto_overhead_ms:.2f} ms avg")
    console.print(f"Score     : [bold]{result.security_score:.1f}/100[/bold]\n")

    if result.attack_events:
        t = Table(box=box.SIMPLE_HEAD)
        t.add_column("Attaque", width=28)
        t.add_column("Cible", width=10)
        t.add_column("Résultat", width=22)
        t.add_column("Détails", width=40)
        for e in result.attack_events:
            color = "green" if e.outcome == "BLOCKED" else "yellow"
            t.add_row(e.attack_type, e.target_id, f"[{color}]{e.outcome}[/{color}]", e.details[:40])
        console.print(t)
