"""Operations supporting mso_mdoc issuance."""
import os
import json
import logging
from binascii import hexlify
from typing import Any, Mapping, Optional
from pydid import DIDUrl
from aries_cloudagent.core.profile import Profile
from aries_cloudagent.wallet.default_verification_key_strategy import (
    BaseVerificationKeyStrategy,
)
from aries_cloudagent.wallet.base import BaseWallet
from aries_cloudagent.wallet.util import b64_to_bytes, bytes_to_b64
import cbor2
from pycose.keys import CoseKey
from ..mso import MsoIssuer
from ..x509 import selfsigned_x509cert

LOGGER = logging.getLogger(__name__)
MDOC_TYPE = "org.iso.18013.5.1.mDL"


def dict_to_b64(value: Mapping[str, Any]) -> str:
    """Encode a dictionary as a b64 string."""
    return bytes_to_b64(json.dumps(value).encode(), urlsafe=True, pad=False)


def b64_to_dict(value: str) -> Mapping[str, Any]:
    """Decode a dictionary from a b64 encoded value."""
    return json.loads(b64_to_bytes(value, urlsafe=True))


def nym_to_did(value: str) -> str:
    """Return a did from nym if passed value is nym, else return value."""
    return value if value.startswith("did:") else f"did:sov:{value}"


def did_lookup_name(value: str) -> str:
    """Return the value used to lookup a DID in the wallet.

    If value is did:sov, return the unqualified value. Else, return value.
    """
    return value.split(":", 3)[2] if value.startswith("did:sov:") else value


async def mso_mdoc_sign(
    profile: Profile,
    headers: Mapping[str, Any],
    payload: Mapping[str, Any],
    did: Optional[str] = None,
    verification_method: Optional[str] = None,
) -> str:
    """Create a signed mso_mdoc given headers, payload, and signing DID or DID URL."""
    if verification_method is None:
        if did is None:
            raise ValueError("did or verificationMethod required.")

        did = nym_to_did(did)

        verkey_strat = profile.inject(BaseVerificationKeyStrategy)
        verification_method = await verkey_strat.get_verification_method_id_for_did(
            did, profile
        )
        if not verification_method:
            raise ValueError("Could not determine verification method from DID")
    else:
        # We look up keys by did for now
        did = DIDUrl.parse(verification_method).did
        if not did:
            raise ValueError("DID URL must be absolute")

    async with profile.session() as session:
        wallet = session.inject(BaseWallet)
        LOGGER.info(f"mso_mdoc sign: {did}")
        did_info = await wallet.get_local_did(did_lookup_name(did))
        key_pair = await wallet._session.handle.fetch_key(did_info.verkey)
        jwk_bytes = key_pair.key.get_jwk_secret()
        jwk = json.loads(jwk_bytes)
        """
        jwk = {
            "kty" : "EC2",
            "crv" : "P_256",
            "x"   : "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
            "y"   : "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
            "d"   : "0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk"
        }
        """
        pk_dict = {
            "KTY": jwk.get("kty") or "",  # OKP, EC
            "CURVE": jwk.get("crv") or "",  # ED25519, P_256
            "ALG": "EdDSA" if jwk.get("kty") == "OKP" else "ES256",
            "D": b64_to_bytes(jwk.get("d") or "", True),  # EdDSA
            "X": b64_to_bytes(jwk.get("x") or "", True),  # EdDSA, EcDSA
            "Y": b64_to_bytes(jwk.get("y") or "", True),  # EcDSA
            "KID": os.urandom(32),
        }

        cose_key = CoseKey.from_dict(pk_dict)
        if isinstance(payload, dict):
            data = [{"doctype": MDOC_TYPE, "data": payload}]
        documents = []
        for doc in data:
            _cert = selfsigned_x509cert(private_key=cose_key)
            msoi = MsoIssuer(data=doc["data"], private_key=cose_key, x509_cert=_cert)
            mso = msoi.sign(device_key=(headers.get("deviceKey") or ""),
                            doctype=MDOC_TYPE)
            document = {
                "docType": MDOC_TYPE,
                "issuerSigned": {
                    "nameSpaces": {
                        ns: [cbor2.CBORTag(24, value={k: v}) for k, v in dgst.items()]
                        for ns, dgst in msoi.disclosure_map.items()
                    },
                    "issuerAuth": mso.encode(),
                },
                # this is required during the presentation.
                #  'deviceSigned': {
                #  # TODO
                #  }
            }
            documents.append(document)

        signed = {
            "version": "1.0",
            "documents": documents,
            "status": 0,
        }
        signed_hex = hexlify(cbor2.dumps(signed))

    return f"{signed_hex}"
