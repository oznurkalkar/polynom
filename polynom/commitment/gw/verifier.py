from __future__ import annotations
from polynom.commitment.bdfg.common import MultiBDFGCommon
from polynom.commitment.bdfg.prover import BatchBDFGProverKey, MultiBDFGProverKey
from polynom.commitment.bdfg.verifier import BDFGVerifier, BatchBDFGVerifierKey, MultiBDFGVerifierKey
from polynom.commitment.gw.common import GWCommon
from polynom.commitment.kzg_base import KZGProverBase
from polynom.ecc import Scalar




class GWVerifier(BDFGVerifier):

    def new_single_key(self, shifts: list[int]) -> MultiBDFGVerifierKey:
        return MultiBDFGVerifierKey(self.w, shifts)

    def new_batch_key(self, openings: list[MultiBDFGVerifierKey]) -> BatchBDFGVerifierKey:
        return BatchBDFGVerifierKey(self.w, openings)

    def verify_single(self, proof: bytes, key: MultiBDFGVerifierKey) -> bool:

        return BDFGVerifier.verify_single(self, proof, key)

    def verify_batch(self, proof: bytes, key: BatchBDFGVerifierKey) -> bool:
        return super().verifiy_batch(proof, key)