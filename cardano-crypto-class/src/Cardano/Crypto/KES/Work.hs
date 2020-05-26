module Work where

import KES

import Cardano.Crypto.KES.Class

foo ::  KESAlgorithm v => proxy v -> String
foo x =  algorithmNameKES x

bar :: SecretKey -> IO ()
bar = update