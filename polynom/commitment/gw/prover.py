from __future__ import annotations
from polynom.commitment.bdfg.prover import BDFGProver, BatchBDFGProverKey, MultiBDFGProverKey
from polynom.commitment.gw.common import GWCommon
from polynom.commitment.kzg_base import KZGProverBase
from polynom.ecc import Scalar
from polynom.polynomial import Polynomial
from polynom.domain import Domain
from polynom.proof_system.transcript.transcript import Transcript
from polynom.lc import LinearCombination


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


class BatchGWProverKey():

    def __init__(self, domain: Domain, openings: list[GWProverKey]):
        self.openings = openings
        self.domain = domain

    def polynomials(self) -> list[Polynomial]:
        return [opening.polys for opening in self.openings]



class GWProver(KZGProverBase):

    def new_single_key(self, polys: list[Polynomial], shifts: list[int]):
        return GWProverKey(self.domain, polys, shifts)

    def new_batch_key(self, openings: list[GWProverKey]) -> BatchGWProverKey:
        return BatchGWProverKey(self.domain, openings)

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


    def create_proof_batch(self, batch: BatchGWProverKey) -> bytes:

        transcript = self.new_transcript()

        #combine f_ij into f_i
        batch_poly = [s.combine() for s in batch.openings]
        
        # commit to f_i(X) and write commitments to the transcript
        [transcript.write_point(self.commit(bp)) for bp in batch_poly]
            
        # get evaluation seed
        z = transcript.challenge()

        multi_bdfgs = [MultiBDFGProverKey(self.domain, batch_poly[_], batch.openings[_].shifts) for _ in range(len(batch_poly))]

        batch_bdfg = BatchBDFGProverKey(self.domain, multi_bdfgs)

        # evaluate polynomials at shifted values of z_i
        # [f(z_i0), f(z_i1), ...]
        evals = batch_bdfg.evaluate(z)
        # write evaluations to the transcript
        [[transcript.write_scalar(eval) for eval in evals_i] for evals_i in evals]

        # get combination base
        alpha = LinearCombination(transcript.challenge())

        # calculate first quotient h(X)
        h_x = batch_bdfg.quotient_polynomial(alpha,z)
        
        # commit to the first quotient and write it to the transcript
        transcript.write_point(self.commit(h_x))
     
        # get linearisation point
        x = transcript.challenge()

        # calculate second quotient
        h2_x = batch_bdfg.linearized_quotient_polynomial(alpha, z, x)
        # commit to the scond quotient and write it to the transcript
        transcript.write_point(self.commit(h2_x))

        # return proof
        return transcript.get_message()

