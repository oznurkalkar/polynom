from polynom.commitment.bdfg.common import MultiBDFGCommon
from polynom.ecc import Scalar
from polynom.polynomial import Polynomial



class GWCommon(MultiBDFGCommon):

    def __init__(self, w: Scalar, shifts: list[int]):
        
        super().__init__(w, shifts)
        
    