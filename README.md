![TravisCI](https://travis-ci.org/TomMD/DRBG.svg)

The Deterministic Random Bit Generator (DRBG) is a collection of
cryptographically secure random bit generators and modifiers written to the
NIST 800-90 specification.  Namely, the HMAC and Hash generators are
implemented and pass the known answer tests (KATS) while the CTR based
generator exists with the intent of matching spec but does not pass KATS for
unknown reasons (mis-interpretation of KATS or otherwise).

The combinators allow users to combine two or more generators for new desired
effects, such as XORing two generators together, using one generator to reseed
another (for obtaining a longer lifetime, presumably), and precomputing randoms
in batch (buffering).
