from __future__ import annotations
from polynom.commitment.bdfg.prover import BDFGProver, MultiBDFGProverKey
from polynom.commitment.gw.common import GWCommon
from polynom.commitment.kzg_base import KZGProverBase
from polynom.ecc import Scalar
from polynom.polynomial import Polynomial
from polynom.domain import Domain
from polynom.proof_system.transcript.transcript import Transcript


class GWProverKey(GWCommon):

    def __init__(self, domain: Domain,  polys: list[Polynomial], shifts: list[int]):

        super().__init__(domain.w(), shifts)
        self.domain = domain
        self.polys = polys

    def combine(self):

        t = len(self.polys)
        max_degree = max(poly.degree() for poly in self.polys)
        newcoeffs = [0] * t*(max_degree + 1)
        for i, poly in enumerate(self.polys) :
            for j, coeff in enumerate(poly.coeffs) :
                newcoeffs[j*t + i] = coeff
        return Polynomial.from_ints(newcoeffs)

    




class GWProver(KZGProverBase):

    def new_single_key(self, polys: list[Polynomial], shifts: list[int]):
        return GWProverKey(self.domain, polys, shifts)

    def create_proof_single(self, multi_poly: GWProverKey) -> bytes:

        transcript = self.new_transcript()

        #combine f_1, f_2, ... , f_t into a single f
        poly = multi_poly.combine()
        
        # commit to the polynomial f(X) and write it to the trascript
        transcript.write_point(self.commit(poly))

        # get evaluation seed
        # assumed that z is a t^th root of unity
        z = transcript.challenge()

        # evaluate polynomial at shifted values of z
        # [f(z_0), f(z_1), ...]
        # then write them to the transcript
        multi_bdfg = MultiBDFGProverKey(self.domain, poly, multi_poly.shifts)
        [transcript.write_scalar(eval) for eval in multi_bdfg.evaluate(z)]

        # calculate first quotient h(X)
        # commit to the quotient W = com(h(X))
        # write it to the transcript
        transcript.write_point(self.commit(multi_bdfg.quotient_polynomial(z)))

         # get linearisation point
        x = transcript.challenge()

        # same goes for second quotient h'(X)
        transcript.write_point(self.commit(multi_bdfg.linearized_quotient_polynomial(z, x)))
        return transcript.get_message()


