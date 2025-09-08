module Cardano.ForeignChecks.TH (
  ensureExactVersion,
  ensureExactVersionOrCommit,
) where

import Control.Exception (SomeException, try)
import Control.Monad (unless)
import Data.Char (isDigit, isSpace)
import Data.List (dropWhileEnd, intercalate, isPrefixOf)
import Data.Maybe (fromMaybe)
import Language.Haskell.TH
import System.Process (readProcess)
import Text.Read (readMaybe)

-- | Trim leading/trailing whitespace (readProcess usually leaves a trailing '\n').
trim :: String -> String
trim = dropWhileEnd isSpace . dropWhile isSpace

getModVersion :: String -> IO (Either String String)
getModVersion pkg = do
  r <- try (readProcess "pkg-config" ["--modversion", pkg] "") :: IO (Either SomeException String)
  case r of
    Left e -> pure (Left ("could not run pkg-config for " ++ pkg ++ ": " ++ show e))
    Right v -> pure (Right (trim v))

ensure :: String -> (String -> Bool) -> String -> Q [Dec]
ensure pkg ok requirement = do
  mv <- runIO (getModVersion pkg)
  case mv of
    Left err -> fail err
    Right v -> do
      unless (ok v) $
        fail (pkg ++ " version/commit '" ++ v ++ "' does not satisfy " ++ requirement)
      pure []

-- | Split a string on '.' into components.
splitOnDot :: String -> [String]
splitOnDot [] = []
splitOnDot s =
  let (h, t) = break (== '.') s
   in h : case t of
        [] -> []
        (_ : xs) -> splitOnDot xs

-- | Parse "A.B.C" into a triple, defaulting missing/garbage parts to 0.
parseTriple :: String -> (Int, Int, Int)
parseTriple s =
  let toNum t = fromMaybe 0 (readMaybe (takeWhile isDigit t) :: Maybe Int)
   in case splitOnDot s of
        (a : b : c : _) -> (toNum a, toNum b, toNum c)
        (a : b : _) -> (toNum a, toNum b, 0)
        (a : _) -> (toNum a, 0, 0)
        _ -> (0, 0, 0)

-- | Pretty-print a triple as "A.B.C".
prettyT :: (Int, Int, Int) -> String
prettyT (a, b, c) = intercalate "." (map show [a, b, c])

ensureExactVersion :: String -> (Int, Int, Int) -> Q [Dec]
ensureExactVersion pkg exactT =
  let req = "== " ++ prettyT exactT
   in ensure pkg (\v -> parseTriple v == exactT) req

-- | True if any approved commit hash has a prefix v.
commitAllowed :: [String] -> String -> Bool
commitAllowed commits v = any (v `isPrefixOf`) commits

-- | Accept either an exact version or an approved commit hash.
ensureExactVersionOrCommit ::
  -- | pkg-config package
  String ->
  -- | exact required version
  Maybe (Int, Int, Int) ->
  -- | approved commit hashes (prefix match)
  [String] ->
  Q [Dec]
ensureExactVersionOrCommit pkg exact commits =
  let versionOK v = maybe False (\e -> parseTriple v == e) exact
      ok v = commitAllowed commits v || versionOK v
      requirement = case exact of
        Just e -> "== " ++ prettyT e ++ " OR one of commits " ++ show commits
        Nothing -> "one of commits " ++ show commits
   in ensure pkg ok requirement
