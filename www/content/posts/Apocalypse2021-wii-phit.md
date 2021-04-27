---
title: "Cyber Apocalypse 2021 2/5 - Wii-Phit"
date: 2021-04-28T12:00:01+01:00
draft: false
author: "Colas Le Guernic"
tags:
  - CTF
  - Writeup
  - CyberApocalypse2021
---


**Wii-Phit** was the only _Hard_ crypto challenge designed by [CryptoHack](https://cryptohack.org/) for the [Cyber Apocalypse 2021](https://www.hackthebox.eu/cyber-apocalypse-ctf-2021) CTF (there were also 4 challenges categorized as _Insane_ though).

There is already an excellent [writeup](https://blog.cryptohack.org/cyber-apocalypse-2021#wii-phit) by the challenge organizers:
one could recognize a well known equation related to the [Erdős–Straus conjecture](https://en.wikipedia.org/wiki/Erd%C5%91s%E2%80%93Straus_conjecture), some participants used [Z3](https://github.com/Z3Prover/z3).
We took a different approach.

<!--more-->

The main difficulty is to find an integer solution to

∳∳
w(xz + yz - xy) == 4xyz
∳∳

where ∳w∳ is a given 512 bits integer.

More specifically, the flag is encrypted with RSA, the prime factors ∳p∳ and ∳q∳ are obviously secret, but we know that they pass the following assert:

```python
w = 25965460884749769384351428855708318685345170011800821829011862918688758545847199832834284337871947234627057905530743956554688825819477516944610078633662855
x = p + 1328
y = p + 1329
z = q - 1

assert w*(x*z + y*z - x*y) == 4*x*y*z
```

Before really starting we can observe that ∳y∳ is ∳x + 1∳ and thus ∳x∳ and ∳y∳ are coprime.
Moreover we know a few factors of ∳w∳ thanks to [factordb.com](http://factordb.com/index.php?query=25965460884749769384351428855708318685345170011800821829011862918688758545847199832834284337871947234627057905530743956554688825819477516944610078633662855).

If we rewrite the assert to put all the multiples of ∳z∳ on the same side we get:

∳∳
\\begin{aligned}
w(xz + yz) - 4xyz &= wxy\\\\
(w(x + y) - 4xy)z &= wxy
\\end{aligned}
∳∳

Thus ∳wxy∳ is a multiple of ∳z∳, in other words: ∳z∳ divides ∳wxy∳.

Similarly ∳x∳ divides ∳wyz∳, and ∳y∳ divides ∳wxz∳.

But ∳x∳ and ∳y∳ are coprime, thus:
- _∳x∳ divides ∳wyz∳_ implies that ∳x∳ divides ∳wz∳
- similarly ∳y∳ divides ∳wz∳

Again, using the fact that ∳x∳ and ∳y∳ are coprime we can deduce that ∳xy∳ divides ∳wz∳, since they both divide ∳wz∳.

As a consequence, we know that there exist two integers ∳α∳ and ∳β∳ such that:

∳∳
\\begin{aligned}
wxy = αz\\\\
wz = βxy
\\end{aligned}
∳∳

Taking the product leads to ∳w^2xyz = αβxyz∳ or ∳w^2 = αβ∳ after simplification.
We know some factors of ∳w^2∳, by distributing them over ∳α∳ and ∳β∳ we may find their values.

We now have a set of candidates for ∳α∳ and ∳β∳.
By using ∳wxy = αz∳ and ∳y = x + 1∳ we can rewrite our original assert as a degree 2 equation in ∳x∳:

∳∳
\\begin{aligned}
w(xz + yz - xy) &= 4xyz\\\\
wxz + w(x+1)z - αz &= 4x(x+1)z\\\\
wx + w(x+1) - α &= 4x(x+1)\\\\
4x^2 + (4 - 2w)x + α - w &= 0
\\end{aligned}
∳∳

Now all we have to do is solve this equation for all the ∳α∳ we were able to build, looking for an integer solution.
That is what we did and it found a suitable solution for ∳α = 1∳.
It is then rather straightforward to get ∳p∳, ∳q∳, and the RSA private key (beware of the unusual ∳φ(N)∳), leading to the flag:

```
CHTB{Erdos-Straus-Conjecture}
```

Our script can be found below.

This is how we solved the challenge, but we were curious about the [Erdős–Straus conjecture](https://en.wikipedia.org/wiki/Erd%C5%91s%E2%80%93Straus_conjecture) and looked back at our equation with ∳α = 1∳.

We have the following determinant:

∳∳
\\begin{aligned}
Δ &= (4 - 2w)^2 - 4\times{}4(1-w)\\\\
Δ &= 16 - 16w + 4w^2 - 16 + 16w\\\\
Δ &= (2w)^2
\\end{aligned}
∳∳

Which gives the following positive solution:

∳∳
\\begin{aligned}
x &= (- (4 - 2w) + √Δ) / (2\times{}4)\\\\
x &= (w-1)/2
\\end{aligned}
∳∳

Then ∳y = (w+1)/2∳ and ∳z = w(w-1)(w+1)/4∳.

We actually did not need to know any factor of ∳w∳, we just needed it to be positive and odd.
But knowing some factors and the fact that ∳y = x + 1∳ gently pushed us in the right direction to rediscover the decomposition mentioned in the wikipedia article on the [Erdős–Straus conjecture](https://en.wikipedia.org/wiki/Erd%C5%91s%E2%80%93Straus_conjecture#Negative-number_solutions).

Here is (a cleaned-up version of) the code we used to find ∳p∳ and ∳q∳ and get the flag:

```python
from itertools import combinations
from math import isqrt, prod


# Challenge Data
cipher = 0x12F47F77C4B5A72A0D14A066FEDC80BA6064058C900A798F1658DE60F13E1D8F21106654C4AAC740FD5E2D7CF62F0D3284C2686D2AAC261E35576DF989185FEE449C20EFA171FF3D168A04BCE84E51AF255383A59ED42583E93481CBFB24FDDDA16E0A767BFF622A4753E1A5DF248AF14C9AD50F842BE47EBB930604BECFD4AF04D21C0B2248A16CDEE16A04B4A12AC7E2161CB63E2D86999A1A8ED2A8FAEB4F4986C2A3FBD5916EFFB1D9F3F04E330FDD8179EA6952B14F758D385C4BC9C5AE30F516C17B23C7C6B9DBE40E16E90D8734BAEB69FED12149174B22ADD6B96750E4416CA7ADDF70BCEC9210B967991E487A4542899DDE3ABF3A91BBBAEFFAE67831C46C2238E6E5F4D8004543247FAE7FF25BBB01A1AB3196D8A9CFD693096AABEC46C2095F2A82A408F688BBEDDDC407B328D4EA5394348285F48AFEAAFACC333CFF3822E791B9940121B73F4E31C93C6B72BA3EDE7BBA87419B154DC6099EC95F56ED74FB5C55D9D8B3B8C0FC7DE99F344BEB118AC3D4333EB692710EAA7FD22
exponent = 0x10001
w = 25965460884749769384351428855708318685345170011800821829011862918688758545847199832834284337871947234627057905530743956554688825819477516944610078633662855

# known factors of w*w
FACTORS = [
    3,
    3,
    5,
    7,
    13,
    29,
    434042467,
    2653449587,
    829389339613,
    83650191286538267,
    2736375417317167558343187941866480708142084464122192435130859730622053555029655238941106280888782037819,
]
FACTORS += FACTORS


def decrypt_flag(p, q):
    N = p ** 3 * q
    phi = p ** 2 * (p - 1) * (q - 1)
    d = pow(exponent, -1, phi)
    m = pow(cipher, d, N)
    flag = m.to_bytes((m.bit_length() + 7) // 8, "big")

    print(f"{flag=}")


def check_candidate(alpha):
    # we are trying to solve: 4*x² + (4 - 2*w)*x + alpha - w = 0
    a = 4
    b = 4 - 2 * w
    c = alpha - w
    delta = b ** 2 - 4 * a * c

    if delta < 0:
        return

    # sqrt may fail if delta is too big, we use isqrt instead
    # but we have to check if we got the actual square root
    sqrt_delta = isqrt(delta)
    if sqrt_delta ** 2 != delta:
        return

    # solutions are (-b +/- sqrt_delta) / (2*a)
    # division may fail if operands are too big
    for x in [-b - sqrt_delta, -b + sqrt_delta]:
        if x <= 0 or x % (2 * a) != 0:
            # x is not a positive integer
            continue

        x = x // (2 * a)
        y = x + 1
        if w * x * y % alpha != 0:
            # z = (w * x * y) / alpha is not an integer
            continue

        z = (w * x * y) // alpha

        p = x - 1328
        q = z + 1

        decrypt_flag(p, q)


# number of factors considered to build alpha
nbr_factors = 0

while nbr_factors <= len(FACTORS):
    worklist = combinations(FACTORS, nbr_factors)

    for alpha_factors in worklist:
        check_candidate(prod(alpha_factors))

    nbr_factors += 1
```
