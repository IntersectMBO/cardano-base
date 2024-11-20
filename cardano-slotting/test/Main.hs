import Test.Cardano.Slotting.EpochInfo (epochInfoTests)
import Test.Tasty

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "EpochInfo" [epochInfoTests]
