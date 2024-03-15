{-# LANGUAGE CPP #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE ForeignFunctionInterface #-}

module Cardano.Git.Rev
  ( gitRev
  ) where

import           Data.Text (Text)
import qualified Data.Text as Text

import           Foreign.C.String (CString)
import           GHC.Foreign (peekCStringLen)
import           Language.Haskell.TH (Exp, Q)
import qualified Language.Haskell.TH as TH
import qualified Language.Haskell.TH.Syntax as TH
import           System.IO (utf8)
import           System.IO.Unsafe (unsafeDupablePerformIO)

#if !defined(arm_HOST_ARCH)
import           Control.Exception (catch)
import           System.Exit (ExitCode (..))
import qualified System.IO as IO
import           System.IO.Error (isDoesNotExistError)
import           System.Process (readProcessWithExitCode)
#endif

foreign import ccall "&_cardano_git_rev" c_gitrev :: CString

-- This must be a TH splice to ensure the git commit is captured at build time.
-- ie called as `$(gitRev)`.
gitRev :: Q Exp
gitRev =
    [| if
         | gitRevEmbed /= zeroRev -> gitRevEmbed
         | otherwise              -> $(textE =<< TH.runIO runGitRevParse)
    |]

-- Git revision embedded after compilation using
-- Data.FileEmbed.injectWith. If nothing has been injected,
-- this will be filled with 0 characters.
gitRevEmbed :: Text
gitRevEmbed = Text.pack $ drop 28 $ unsafeDupablePerformIO (peekCStringLen utf8 (c_gitrev, 68))

runGitRevParse :: IO Text
#if defined(arm_HOST_ARCH)
-- cross compiling to arm fails; due to a linker bug
runGitRevParse = pure zeroRev
#else
runGitRevParse = do
    (exitCode, output, errorMessage) <- readProcessWithExitCode_ "git" ["rev-parse", "--verify", "HEAD"] ""
    case exitCode of
      ExitSuccess -> pure $ Text.strip (Text.pack output)
      ExitFailure _ -> do
        IO.hPutStrLn IO.stderr $ "WARNING: " ++ errorMessage
        pure zeroRev
  where
    readProcessWithExitCode_ :: FilePath -> [String] -> String -> IO (ExitCode, String, String)
    readProcessWithExitCode_ cmd args input =
      catch (readProcessWithExitCode cmd args input) $ \e ->
      if isDoesNotExistError e
        then pure (ExitFailure 127, "", show e)
        else pure (ExitFailure 999, "", show e)
#endif

textE :: Text -> Q Exp
textE = TH.lift

zeroRev :: Text
zeroRev = "0000000000000000000000000000000000000000"
