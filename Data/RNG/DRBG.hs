module Data.RNG.DRBG

type Entropy = B.ByteString
type PersonalizationString = B.ByteString
type Nonce = B.ByteString
type AdditionalInput = B.ByteString
type RandomBits = B.ByteString

class DRBG g s | g -> s where
  instantiate :: (Hash h c d) => h -> Entropy -> Nonce -> PersonalizationString -> s h
  reseed :: (Hash h c d) => s h -> Entropy -> AdditionalInput -> State h
  generate :: (Hash h c d) => s h -> BitLen -> AdditionalInput -> Maybe (RandomBits, s h)
  
