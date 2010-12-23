module Crypto.Random.DRBG.Types where

import Data.ByteString as B
import Data.ByteString.Lazy as L

type BitLen = Int
type Entropy = B.ByteString
type PersonalizationString = B.ByteString
type Nonce = B.ByteString
type AdditionalInput = B.ByteString
type RandomBits = B.ByteString
