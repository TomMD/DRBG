module Data.DRBG where

import Data.ByteString as B

type Entropy = B.ByteString
type PersonalizationString = B.ByteString
type Nonce = B.ByteString
type AdditionalInput = B.ByteString
type RandomBits = B.ByteString
