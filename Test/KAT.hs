{-# LANGUAGE EmptyDataDecls, MultiParamTypeClasses #-}
import qualified Data.DRBG.Hash as H
import qualified Data.DRBG.HMAC as M
import Data.CryptoHash.SHA256 as SHA
import qualified Data.ByteString as B
import Data.Crypto.Classes
import Data.Serialize as Ser
import Data.Serialize.Put as S
import Data.Binary as Bin
import Data.Binary.Put as P
import Text.PrettyPrint.HughesPJClass
import qualified Data.ByteString.Lazy.Char8 as L
import qualified Data.ByteString.Lazy as LN
import Data.Bits (shiftR, shiftL)
import Data.Crypto.HMAC
import Data.Crypto.Types
import Data.Bits (xor)
import Data.Tagged
import Data.Maybe (maybeToList)
import Data.List (deleteBy)
import Test.Crypto
import Test.ParseNistKATs
import Text.Parsec.ByteString

newtype SHADigest = SHADigest B.ByteString
	deriving (Eq, Ord, Show)

instance Hash SHA.Ctx SHADigest where
  outputLength = Tagged 256
  initialCtx = SHA.init
  updateCtx = SHA.update
  finalize ctx = SHADigest . SHA.finalize . SHA.update ctx
  strength = Tagged 256
  blockLength = Tagged 512

instance H.SeedLength SHADigest where
	seedlen = Tagged 440

instance Serialize SHADigest where
	get = undefined
	put (SHADigest d) = S.putByteString d

instance Binary SHADigest where
	get = undefined
	put (SHADigest d) = P.putByteString d

main = hmacMain >> hashMain >> hmacCipher

-- Verify the HMAC implementation
hmacCipher = do
	print (Ser.encode (hmac k d `asTypeOf` hsh) == res)
  where
  calcVal = Ser.encode (hmac k d `asTypeOf` hsh)
  hash = hashFunc hsh
  hsh = (undefined :: SHADigest)
  k = B.replicate 32 0x0b
  d = L.pack "Hi There"
  res = i2bs 256 0x198a607eb44bfbc69903a0f1cf2bbdc5ba0aa3f3d9ae3c1c7a3b1696a0b68cf7
  d' = Bin.encode (hash $ L.concat [ki, d])
  k' = Ser.encode (hash (L.fromChunks [k]))
  ki = L.fromChunks [B.map (`xor` 0x36) k']
  ko = L.fromChunks [B.map (`xor` 0x5c) k']


nistTests_HMAC :: IO [Test]
nistTests_HMAC = do
	(Right cats) <- parseFromFile (many parseCategory) "HMAC_DRBG.txt"
	return (concat $ concatMap (maybeToList . categoryToTest_HMAC) cats)

-- Currently run SHA-256 tests only
categoryToTest_HMAC :: TestCategory -> Maybe [Test]
categoryToTest_HMAC (props, ts) =
	if "SHA-256" `notElem` map fst props
		then Nothing
		else let s = unlines $ map showProp props 
			 h = hashFunc (undefined :: SHADigest)
			 tests = concatMap (map katToTest . maybeToList . buildKAT) ts
		     in Just tests
  where
  deleteF k lst = deleteBy (const $ (==) k . fst) undefined lst
  isPR = Just True == fmap read (lookup "PredictionResistance" props)
  showProp (p,"") = '[' : p ++ "]"
  showProp (p,v)  = '[' : p ++ " = " ++ v ++ "]"
  testName = fst (head props) ++ (if isPR then "_PR" else "")
--   buildKat :: [Record] -> Maybe (KAT (String, String, String, String, String, String, String) B.ByteString)
  buildKAT t
	| fmap read (lookup "PredictionResistance" props) == Just True = do
	cnt    <- lookup "COUNT" t
	let name = testName ++ cnt
	eIn    <- lookup "EntropyInput" t
	n      <- lookup "Nonce" t
	per    <- lookup "PersonalizationString" t
	aIn1   <- lookup "AdditionalInput" t
	eInPR1 <- lookup "EntropyInputPR" t
	let t' = deleteF "EntropyInputPR" (deleteF "AdditionalInput" t)
	aIn2   <- lookup "AdditionalInput" t'
	eInPR2 <- lookup "EntropyInputPR" t'
	ret    <- lookup "ReturnedBits" t'
	let f (eIn, n, per, aIn1, eInPR1, aIn2, eInPR2) =
		let hx = hexStringToBS
		    st0 = M.instantiate (hx eIn) (hx n) (hx per) :: M.State SHADigest
		    st1 = M.reseed st0 (hx eInPR1) (hx aIn1)
		    Just (_,st2) = M.generate st1 256 B.empty
		    st3 = M.reseed st2 (hx eInPR2) (hx aIn2)
		    Just (r1,_) = M.generate st3 256 B.empty
		in r1
	return (K (eIn, n, per, aIn1, eInPR1, aIn2, eInPR2) f (L.fromChunks [hexStringToBS ret]) name)
	| otherwise = do
	cnt <- lookup "COUNT" t
	let name = testName ++ cnt
	eIn   <- lookup "EntropyInput" t
	n     <- lookup "Nonce" t
	per   <- lookup "PersonalizationString" t
	aIn1  <- lookup "AdditionalInput" t
	eInRS <- lookup "EntropyInputReseed" t
	aInRS <- lookup "AdditionalInputReseed" t
	let t' = deleteF "AdditionalInput" t
	aIn2  <- lookup "AdditionalInput" t'
	ret   <- lookup "ReturnedBits" t
	let f (eIn, n, per, aIn1, eInRS, aInRS, aIn2) =
		let hx = hexStringToBS
		    st0 = M.instantiate (hx eIn) (hx n) (hx per) :: M.State SHADigest
		    Just (_,st1) = M.generate st0 256 (hx aIn1)
		    st2 = M.reseed st1 (hx eInRS) (hx aInRS)
		    Just (r1, _) = M.generate st2 256 (hx aIn2)
		in r1
	return (K (eIn, n, per, aIn1, eInRS, aInRS, aIn2) f (L.fromChunks [hexStringToBS ret]) name)

-- Test the HMAC DRBG functionallity
hmacMain = nistTests_HMAC >>= runTests

-- Verify the Hash-DRBG operation
hashMain = do
    let st  = H.instantiate entropy nonce personalStr :: H.State SHADigest
	Just (_,st') = H.generate st 256 additional
	st'' = H.reseed st' reseedIn additional
	Just (rb1, _) = H.generate st'' 256 additional
    print [rb1 == res]
  where
  hsh = (undefined :: SHADigest) 
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

