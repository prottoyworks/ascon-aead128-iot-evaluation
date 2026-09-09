"""Deterministic serialisation and the AAD / payload split.

Cryptographic primitives operate on byte strings, so every message must be
converted to bytes by a process that is *deterministic*: the same reading must
always produce the same bytes, on any machine, in any Python process.  If it
did not, two things would break at once -- the receiver could not reconstruct
the associated data to verify the tag, and the benchmark's "message size" axis
would wobble between runs.

Canonicalisation rules used here
-------------------------------
* JSON object keys are sorted (``sort_keys=True``).
* No insignificant whitespace (``separators=(",", ":")``).
* UTF-8 output, non-ASCII preserved rather than escaped.
* Floats are rounded at generation time (see ``src/sensor.py``) so that
  ``repr`` differences can never appear.

This is a *project-local* canonicalisation, deliberately simple and easy to
audit.  A production protocol would more likely use a binary encoding such as
CBOR (RFC 8949) with deterministic encoding rules, which would shrink messages
considerably; that is noted as future work rather than adopted here, because
JSON keeps the encoded bytes human-inspectable during marking.

The AAD / payload split
-----------------------
An AEAD scheme accepts two inputs that it treats differently:

*Associated data (AAD)* is authenticated but **not** encrypted.  It travels in
clear.  Use it for the fields a network needs to read in order to route,
demultiplex or filter a message before it can be decrypted.

*Plaintext* is both authenticated **and** encrypted.

For this study:

======================================  ==============  ===================
Field                                   Placement       Reason
======================================  ==============  ===================
``device_id``                           AAD             Gateway must route on it
``protocol_version``                    AAD             Needed to parse the rest
``sequence``                            AAD             Replay filter runs pre-decrypt
``temperature``/``humidity``/``gas``    Encrypted       Reveals warehouse conditions
``timestamp``                           Encrypted       Reveals activity patterns
======================================  ==============  ===================

The crucial property is that AAD being *readable* does not make it
*modifiable*.  The AAD bytes are absorbed into the AEAD state before the tag
is computed, so flipping a single bit of ``device_id`` in transit changes the
tag the receiver computes, and verification fails.  An attacker can read
``WH-001``; an attacker cannot change it to ``WH-999`` and have the message
accepted.  ``src/security_tests.py`` demonstrates this empirically.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .sensor import SensorReading

#: Fields transmitted in clear but authenticated.
AAD_FIELDS: tuple[str, ...] = ("device_id", "protocol_version", "sequence")
#: Fields encrypted and authenticated.
PAYLOAD_FIELDS: tuple[str, ...] = ("temperature", "humidity", "gas_level", "timestamp")


def canonical_json_bytes(obj: dict[str, object]) -> bytes:
    """Serialise a dict to canonical, deterministic UTF-8 JSON bytes."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def parse_json_bytes(raw: bytes) -> dict[str, object]:
    """Inverse of :func:`canonical_json_bytes`.

    Raises:
        ValueError: if the bytes are not valid UTF-8 JSON describing an object.
    """
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Payload is not valid UTF-8 JSON.") from exc
    if not isinstance(obj, dict):
        raise ValueError("Payload JSON is not an object.")
    return obj


def build_aad(reading: SensorReading) -> bytes:
    """Return the associated-data bytes for a reading."""
    data = reading.to_dict()
    return canonical_json_bytes({field: data[field] for field in AAD_FIELDS})


def build_payload(reading: SensorReading) -> bytes:
    """Return the to-be-encrypted plaintext bytes for a reading."""
    data = reading.to_dict()
    return canonical_json_bytes({field: data[field] for field in PAYLOAD_FIELDS})


def split_reading(reading: SensorReading) -> tuple[bytes, bytes]:
    """Return ``(aad_bytes, plaintext_bytes)`` for a reading."""
    return build_aad(reading), build_payload(reading)


def reassemble(aad: bytes, plaintext: bytes) -> SensorReading:
    """Rebuild a :class:`SensorReading` from verified AAD and plaintext.

    This is only ever called *after* AEAD verification has succeeded, so the
    inputs are known-authentic.  It still validates structure, because a
    genuine sender could be running an incompatible protocol version.

    Raises:
        ValueError: if a required field is missing or mistyped.
    """
    merged: dict[str, object] = {}
    merged.update(parse_json_bytes(aad))
    merged.update(parse_json_bytes(plaintext))

    missing = [f for f in AAD_FIELDS + PAYLOAD_FIELDS if f not in merged]
    if missing:
        raise ValueError(f"Message is missing required field(s): {', '.join(missing)}")
    try:
        return SensorReading(
            device_id=str(merged["device_id"]),
            protocol_version=int(merged["protocol_version"]),  # type: ignore[arg-type]
            sequence=int(merged["sequence"]),                  # type: ignore[arg-type]
            temperature=float(merged["temperature"]),          # type: ignore[arg-type]
            humidity=float(merged["humidity"]),                # type: ignore[arg-type]
            gas_level=int(merged["gas_level"]),                # type: ignore[arg-type]
            timestamp=str(merged["timestamp"]),
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Message field has an unexpected type: {exc}") from exc


@dataclass(frozen=True)
class SecurePacket:
    """What actually goes on the wire.

    Attributes:
        algorithm: Identifier the receiver uses to select a cipher.
        aad: Associated data, readable but authenticated.
        nonce: Per-message nonce; must accompany the ciphertext.
        ciphertext: ``ciphertext || tag``.
    """

    algorithm: str
    aad: bytes
    nonce: bytes
    ciphertext: bytes

    @property
    def wire_size(self) -> int:
        """Total transmitted bytes, excluding lower-layer framing.

        Communication overhead in a constrained network is dominated by what
        must be sent *in addition to* the useful payload, so this deliberately
        counts the AAD and nonce as well as the ciphertext.
        """
        return len(self.aad) + len(self.nonce) + len(self.ciphertext)

    def peek_sequence(self) -> tuple[str, int] | None:
        """Read ``(device_id, sequence)`` from the AAD *before* verification.

        SECURITY NOTE -- read this before using the return value.
        At the moment this method is called the AAD has **not** been
        authenticated, so both values are attacker-controlled.  They are safe
        to use only for a cheap pre-filter that can *reject* a message early;
        they must never be used to *accept* one, and the replay counter must
        not be advanced on their say-so.  ``src/receiver.py`` implements that
        two-phase discipline.

        Returns:
            The pair, or None if the AAD is malformed.
        """
        try:
            obj = parse_json_bytes(self.aad)
            return str(obj["device_id"]), int(obj["sequence"])  # type: ignore[arg-type]
        except (ValueError, KeyError, TypeError):
            return None
