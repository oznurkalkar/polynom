# def __init__(self, root_of_unity: Scalar, s: int, exp: int, k2: Scalar, k: int = 1):

from polynom.ecc.bn254.scalar import Scalar, MODULUS
from polynom.domain import DomainConfig

generator = Scalar(7)
root_of_unity = Scalar(1748695177688661943023146337482803886740723238769601073607632802312037301404)
s = 28
k2 = Scalar(7)
kx = Scalar(0x30644e72e131a029048b6e193fd84104cc37a73fec2bc5e9b8ca0b2d36636f23)

assert root_of_unity == generator**((MODULUS - 1) >> s)


def domain_config(exp: int, k: int = 1) -> DomainConfig:
    return DomainConfig(root_of_unity, s, exp, k2, k)
