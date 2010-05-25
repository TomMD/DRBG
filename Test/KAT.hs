{-# LANGUAGE EmptyDataDecls, MultiParamTypeClasses #-}
import qualified Data.DRBG.Hash as H
import qualified Data.DRBG.HMAC as M
import Data.Digest.Pure.SHA
import Data.ByteString as B
import Data.Crypto.Classes
import Data.Serialize as Ser
import Data.Serialize.Put as S
import Data.Binary as Bin
import Data.Binary.Put as P
import Text.PrettyPrint.HughesPJClass
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Bits (shiftR, shiftL)
import Data.Crypto.HMAC
import Data.Digest.Pure.MD5 as M
import Data.Bits (xor)

data SHA256

instance Show SHA256 where
	show _ = "SHA256"

sha256desc = undefined :: SHA256

instance Hash SHA256 Int Digest where
  outputLength _ = 256
  hashFunction _ = sha256
  initialContext _ = 0
  updateContext = undefined
  finalize = undefined
  strength _ = 256
  blockLength _ = 512

data MD5
instance Show MD5 where
  show _ = "MD5"

instance Hash MD5 MD5Context MD5Digest where
  outputLength _ = 128
  hashFunction _ = M.md5
  initialContext _ = md5InitialContext
  updateContext = md5Update
  finalize = md5Finalize
  strength _ = 128
  blockLength _ = 512

instance H.SeedLength SHA256 where
	seedlen _ = 440

instance Serialize Digest where
	get = undefined
	put d = S.putByteString (B.concat $ L.toChunks (bytestringDigest d))
instance Binary Digest where
	get = undefined
	put = P.putLazyByteString . bytestringDigest

instance Pretty Digest where
	pPrint = undefined

instance Pretty MD5Digest where
	pPrint = undefined

main = hmacMain >> hashMain >> hmacCipher

hmacCipher = do
	print (Ser.encode (hmac hsh k d) == res)
  where
  hash = hashFunction hsh
  hsh = (undefined :: SHA256)
  k = B.replicate 32 0x0b
  d = L.pack "Hi There"
  res = i2bs 256 0x198a607eb44bfbc69903a0f1cf2bbdc5ba0aa3f3d9ae3c1c7a3b1696a0b68cf7
  d' = Bin.encode (hash $ L.concat [ki, d])
  k' = Ser.encode (hash (L.fromChunks [k]))
  ki = L.fromChunks [B.map (`xor` 0x36) k']
  ko = L.fromChunks [B.map (`xor` 0x5c) k']


hmacMain = do
    let st = M.instantiate hsh entropy nonce perstr
	Just (_,st') = M.generate st 256 additional
	st'' = M.reseed st' entropyRS additional
        Just (r1,_) = M.generate st'' 256 additional
    print $ Prelude.map (==res) [r1]
  where
  hsh = (undefined :: SHA256)
  entropy = i2bs 256 0xd267c90786019cf0e82dfbde3864e2364e45ee80f81ad48f95a824eef03d3d8c
  nonce = i2bs 128 0x171e633600ab8fe6d4cab13622315db1
  perstr = B.empty
  additional = B.empty
  entropyRS  = i2bs 256 0xb1177e226b0d306cc914360b570e3ffe918dc1045aff9066c219c102f888c09b
  res = L.fromChunks [i2bs 256 0x2f118de4d28fafb44bced1d26070a2d8dd1b477806ee6136db5dae26bf18e71c]
{-
  entropy = i2bs 256 0xebd11132d7837960500a436e467aba7dd28546faf6e74fa9950c56efb405505e
  nonce = i2bs 128 0x9a5ebbb0fd780a00d52ee438e6f87084
  perstr = B.empty
  additional = B.empty
  entropyRS  = i2bs 256 0x785dd9360f2f52aa9153eb726536fcd470c75a9b6805d63b77c5f74113c8faff
  res = L.fromChunks [i2bs 256 0x98ebbadbee0d67f7b8b70750b0da5e7d90572682b357bf580ed88c94529cce7f]
-}

hashMain = do
    let st  = H.instantiate hsh entropy nonce personalStr
	Just (_,st') = H.generate st 256 additional
	st'' = H.reseed st' reseedIn additional
	Just (rb1, _) = H.generate st'' 256 additional
    print [rb1 == res]
  where
  hsh = (undefined :: SHA256) 
  entropy = i2bs 256 0xc8850054b417efb9325b5782b63b3be7a8a444949d742636d9a5303e04b933fa
  nonce   = i2bs 128 0x52a81de4b094c470abd675eb05695704
  reseedIn = i2bs 256 0xfab438f89d3839fe202e0da304d1479c34e4f574fc5cc0d8465146231a26b62c
  personalStr = B.empty
  additional = B.empty
  res = L.fromChunks [i2bs 256 0xb2a157ceefdeff0582a4d7dfa7d59dad62eca62cb69ca1973a0788a13ccc7894 ]
{-
  entropy = i2bs 256 0x7f8c07b5039309c97e8e868be70f7311dec60faa434ea24e1437764a8656152b
  nonce   = i2bs 128 0xc63a0b0333ceb1604de5ee8344a7d875
  reseedIn = i2bs 256 0xf71ab7dbf37dc4f949732c915f699b7a937ad8d7d63c818283cb07bc7f16eb15
  personalStr = B.empty
  additional = B.empty
  res = L.fromChunks [i2bs 256 0xbde925d138d723faa007f455f13b67c0af46a0a733360533d47766622426c01f ]
-}

i2bs :: BitLength -> Integer -> B.ByteString
i2bs l i = B.unfoldr (\l' -> if l' < 0 then Nothing else Just (fromIntegral (i `shiftR` l'), l' - 8)) (l-8)

bs2i :: B.ByteString -> Integer
bs2i bs = B.foldl' (\i b -> (i `shiftL` 8) + fromIntegral b) 0 bs

