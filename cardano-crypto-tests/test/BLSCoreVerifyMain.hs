module Main (main) where

import Test.Tasty (defaultMain)

import qualified Test.Crypto.BLSCoreVerify

main :: IO ()
main = defaultMain Test.Crypto.BLSCoreVerify.tests
