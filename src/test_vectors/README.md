# BLS Standard Test Vectors
These test vectors are based off the standard found at:

https://github.com/pairingwg/bls_standard/blob/master/minutes/spec-v1.md.

These tests values are based on both this library and the C reference implementation:

https://github.com/kwantam/bls_sigs_ref.

When running the reference implementation to obtain the output run:

`./hash_to_g2 -n 1`

'1', 'Enter', 'Ctrl + d'

`./hash_to_g2 -n 1`

'2', 'Enter', 'Ctrl + d'

`./hash_to_g2 -n 1`

'3', 'Enter', 'Ctrl + d'

## Case01 Hash to Curve Jacobian:
The input is the message as bytes that is parsed to `hash_to_field`.

The output is the final result of hash to curve. It is a Jacobian Projective
of the form (xZ^2, yZ^3, Z). The process includes hashing to field, converting
to  3-Isogeny Point, mapping that to BLS G2 point and finally clearing the
cofactor.

## Case02 Hash to Curve Affine:
The input is the message as bytes that is parsed to `hash_to_field`.

The output is the same as case01 except the point is converted to (x, y) format.

## Case03 Hash to Field G2:
The input is the message as above.

The output are the two Fp2 values resultant from calling `hash_to_field(msg, ctr, p, 2, SHA256, 2)`
twice. First setting `ctr` to 0 then 1.

## Case04 Field Value to Uncleared G2 Jacobian:
The input is the Fp2 values outputted from the Case03.

The output is a BLS G2 point where the co-factor has not been cleared.
It is in Jacobian form (xZ^2, yZ^3, Z).
