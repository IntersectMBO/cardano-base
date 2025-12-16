import Test.Cardano.Slotting.EpochInfo (epochInfoTests)
import Test.Hspec

main :: IO ()
main = hspec tests

tests :: Spec
tests = describe "EpochInfo" epochInfoTests
