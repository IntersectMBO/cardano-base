
module Test.Crypto.Work(test1,test2,test3) where

import Cardano.Crypto.KES.Rust(
  -- Local datatype used in the KESAlgorithm class
   Seed,PublicKey, SecretKey, Signature,
   -- Local functions used in thr KESAlgorihm class
   generate,verify,sign,uodate,period_from,compute_public,
   -- IO version tah call the foreign functions, used in the tests
   generateIO,verifyIO,signIO,updateIO,period_fromIO,compute_publicIO,
   )

import Cardano.Crypto.KES.Class

-- =====================================================

byteString :: String -> ByteString
byteString str = BS.pack (map (fromIntegral . ord) str)

test1 :: IO ()
test1 = do
  putStrLn "test 1"
  seed <- createSeedIO
  (pub, sec) <- generateIO seed
  print pub
  print sec
  let bytes = (byteString "hello world")
  sig <- signIO sec bytes
  print sig
  valid <- verifyIO pub bytes sig
  print valid
  t_val <- compute_publicIO sec
  print t_val

test2 :: IO ()
test2 = do
  putStrLn "test 2"
  seed <- createSeedIO
  let bytes = (byteString "hello world")
      (pub, sec) = generate seed
  print pub
  print sec
  let sig = sign sec bytes
  print sig
  let valid = verify pub bytes sig
  print valid
  let t_val = compute_public sec
  print t_val


test3 :: IO ()
test3 = do
  seed <- createSeedIO
  let bytes = (byteString "hello world")
      sec :: SignKeyKES (RustKES 5)   -- This signature fixes the KESAlgorithm instance
      sec = genKeyKES seed
      public = deriveVerKeyKES sec
      sig = signKES () (0::Period) bytes sec
      valid = verifyKES () public (0::Period) bytes sig
  print sec
  print public
  print sig
  print valid
  let msec = updateKES () sec (0::Period)
  case msec of
     Just sec2 -> print valid2
        where sig2 = signKES () (1::Period) bytes sec2
              valid2 = verifyKES () public (1::Period) bytes sig2
     Nothing -> print "Update failed"
