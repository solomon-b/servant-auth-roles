
{-# OPTIONS_GHC -Wno-orphans #-}

module Servant.Auth.RolesSpec (spec) where

import Servant.Auth.Roles (CheckRole (..), Proof (..), RequireRole, Satisfied, Satisfies (Satisfies), Sing, SomeRole (..))
import Control.Monad.Except (throwError)
import Control.Monad.IO.Class (liftIO)
import Data.ByteString (ByteString)
import Data.Data (Proxy (..))
import Data.IORef (IORef, modifyIORef', newIORef, readIORef)
import Network.HTTP.Types (Header, HeaderName, hAccept)
import Network.Wai (Application, Request, requestHeaders)
import Network.Wai.Test (SResponse)
import Servant.API (Get, JSON, type (:<|>) (..), type (:>))
import Servant.API.Experimental.Auth (AuthProtect)
import Servant.Server (Context (..), Handler, Server, err401, serveWithContext)
import Servant.Server.Experimental.Auth (AuthHandler, AuthServerData, mkAuthHandler)
import Test.Hspec (Spec, describe, it, shouldReturn)
import Test.Hspec.Wai (WaiSession, get, matchStatus, request, shouldRespondWith, with)
import Test.Hspec.Wai.Internal (runWaiSession)

--------------------------------------------------------------------------------
-- Scheme 1: role-indexed auth

data UserRole = Viewer | Editor | Admin
  deriving (Eq, Ord, Show)

data SUserRole (r :: UserRole) where
  SViewer :: SUserRole 'Viewer
  SEditor :: SUserRole 'Editor
  SAdmin :: SUserRole 'Admin

type family (a :: UserRole) <=? (b :: UserRole) :: Bool where
  'Viewer <=? _ = 'True
  'Editor <=? 'Viewer = 'False
  'Editor <=? _ = 'True
  'Admin <=? 'Admin = 'True
  'Admin <=? _ = 'False

type instance
  Satisfied (required :: UserRole) (actual :: UserRole) =
    (required <=? actual) ~ 'True

type instance Sing = SUserRole

instance CheckRole 'Viewer where
  type RoleType 'Viewer = UserRole
  checkRole SViewer = Just Proof
  checkRole SEditor = Just Proof
  checkRole SAdmin = Just Proof

instance CheckRole 'Editor where
  type RoleType 'Editor = UserRole
  checkRole SViewer = Nothing
  checkRole SEditor = Just Proof
  checkRole SAdmin = Just Proof

instance CheckRole 'Admin where
  type RoleType 'Admin = UserRole
  checkRole SViewer = Nothing
  checkRole SEditor = Nothing
  checkRole SAdmin = Just Proof

data RoleAuth (r :: UserRole) = RoleAuth {roleAuthName :: String}
  deriving (Show)

type instance AuthServerData (AuthProtect "role-auth") = SomeRole RoleAuth

parseRole :: Request -> Maybe (SomeRole RoleAuth)
parseRole req = case lookup "X-Role" (requestHeaders req) of
  Just "viewer" -> pure $ SomeRole SViewer (RoleAuth "Reed")
  Just "editor" -> pure $ SomeRole SEditor (RoleAuth "Lyxia")
  Just "admin" -> pure $ SomeRole SAdmin (RoleAuth "Sandy")
  _ -> Nothing

-- | Reads the "X-Role" header to determine the user's role.
-- Missing header -> 401. Values: "viewer", "editor", "admin".
roleAuthHandler :: AuthHandler Request (SomeRole RoleAuth)
roleAuthHandler = mkAuthHandler $ \req ->
  maybe (throwError err401) pure (parseRole req)

banUser :: Proof 'Admin r -> RoleAuth r -> String
banUser _prf auth = "banned by " <> roleAuthName auth

--------------------------------------------------------------------------------
-- Test API (separate paths)

type AdminAPI =
  RequireRole "role-auth" 'Admin
    :> "admin"
    :> Get '[JSON] String

type EditorAPI =
  RequireRole "role-auth" 'Editor
    :> "editor"
    :> Get '[JSON] String

type ViewerAPI =
  RequireRole "role-auth" 'Viewer
    :> "viewer"
    :> Get '[JSON] String

type TestAPI = AdminAPI :<|> EditorAPI :<|> ViewerAPI

testServer :: Server TestAPI
testServer = adminHandler :<|> editorHandler :<|> viewerHandler
  where
    adminHandler :: Satisfies 'Admin RoleAuth -> Handler String
    adminHandler (Satisfies proof auth) = pure (banUser proof auth)

    editorHandler :: Satisfies 'Editor RoleAuth -> Handler String
    editorHandler (Satisfies _proof auth) = pure $ "editor: " <> show (roleAuthName auth)

    viewerHandler :: Satisfies 'Viewer RoleAuth -> Handler String
    viewerHandler (Satisfies _proof auth) = pure $ "viewer: " <> show (roleAuthName auth)

roleApp :: IO Application
roleApp =
  pure $
    serveWithContext
      (Proxy @TestAPI)
      (roleAuthHandler :. EmptyContext)
      testServer

--------------------------------------------------------------------------------
-- Test API (same path, role-based fallthrough)
--
-- Routes ordered most-restrictive-first:
--   Admin  -> "admin panel"
--   Editor -> "editor panel"
--   Viewer -> "viewer panel"

type PanelAdminAPI =
  RequireRole "role-auth" 'Admin
    :> "panel"
    :> Get '[JSON] String

type PanelEditorAPI =
  RequireRole "role-auth" 'Editor
    :> "panel"
    :> Get '[JSON] String

type PanelViewerAPI =
  RequireRole "role-auth" 'Viewer
    :> "panel"
    :> Get '[JSON] String

type FallthroughAPI = PanelAdminAPI :<|> PanelEditorAPI :<|> PanelViewerAPI

fallthroughServer :: Server FallthroughAPI
fallthroughServer = panelAdmin :<|> panelEditor :<|> panelViewer
  where
    panelAdmin :: Satisfies 'Admin RoleAuth -> Handler String
    panelAdmin (Satisfies _proof _auth) = pure "admin panel"

    panelEditor :: Satisfies 'Editor RoleAuth -> Handler String
    panelEditor (Satisfies _proof _auth) = pure "editor panel"

    panelViewer :: Satisfies 'Viewer RoleAuth -> Handler String
    panelViewer (Satisfies _proof _auth) = pure "viewer panel"

fallthroughApp :: IO Application
fallthroughApp =
  pure $
    serveWithContext
      (Proxy @FallthroughAPI)
      (roleAuthHandler :. EmptyContext)
      fallthroughServer

--------------------------------------------------------------------------------
-- Test API (auth invocation counting)

-- | Auth handler that increments an IORef each time it is called.
countingAuthHandler :: IORef Int -> AuthHandler Request (SomeRole RoleAuth)
countingAuthHandler counter = mkAuthHandler $ \req -> do
  Control.Monad.IO.Class.liftIO $ modifyIORef' counter (+ 1)
  maybe (throwError err401) pure (parseRole req)

countingApp :: IORef Int -> IO Application
countingApp counter =
  pure $
    serveWithContext
      (Proxy @FallthroughAPI)
      (countingAuthHandler counter :. EmptyContext)
      fallthroughServer

--------------------------------------------------------------------------------
-- Test API (public route behind role gates)
--
-- Regression guard: a trailing unauthenticated route is UNREACHABLE when it
-- sits behind RequireRole alternatives on the same path. Because authentication
-- failure is fatal, an unauthenticated request short-circuits at the first
-- RequireRole (401) and never falls through to the public route. That route is
-- dead code here: only an authenticated user whose role is below every gate
-- could reach it, and no such role exists in UserRole.

type PanelAnonAPI =
  "panel"
    :> Get '[JSON] String

type AnonFallthroughAPI =
  PanelAdminAPI :<|> PanelEditorAPI :<|> PanelViewerAPI :<|> PanelAnonAPI

anonFallthroughServer :: Server AnonFallthroughAPI
anonFallthroughServer = panelAdmin :<|> panelEditor :<|> panelViewer :<|> panelAnon
  where
    panelAdmin :: Satisfies 'Admin RoleAuth -> Handler String
    panelAdmin _ = pure "admin panel"

    panelEditor :: Satisfies 'Editor RoleAuth -> Handler String
    panelEditor _ = pure "editor panel"

    panelViewer :: Satisfies 'Viewer RoleAuth -> Handler String
    panelViewer _ = pure "viewer panel"

    panelAnon :: Handler String
    panelAnon = pure "anon panel"

anonApp :: IO Application
anonApp =
  pure $
    serveWithContext
      (Proxy @AnonFallthroughAPI)
      (roleAuthHandler :. EmptyContext)
      anonFallthroughServer

--------------------------------------------------------------------------------
-- Scheme 2: flat, non-hierarchical roles (exact match)
--
-- A second scheme living alongside Scheme 1. 'Sing' and 'Satisfied' are open
-- families indexed by kind, so each role type instantiates them independently
-- and the two schemes never interact. Note there is no 'Ord' here: sufficiency
-- is equality, not a hierarchy.

data Region = US | EU | APAC
  deriving (Eq, Show)

data SRegion (r :: Region) where
  SUS :: SRegion 'US
  SEU :: SRegion 'EU
  SAPAC :: SRegion 'APAC

type family (a :: Region) ==? (b :: Region) :: Bool where
  'US ==? 'US = 'True
  'EU ==? 'EU = 'True
  'APAC ==? 'APAC = 'True
  _ ==? _ = 'False

type instance
  Satisfied (required :: Region) (actual :: Region) =
    (required ==? actual) ~ 'True

type instance Sing = SRegion

instance CheckRole 'US where
  type RoleType 'US = Region
  checkRole SUS = Just Proof
  checkRole _ = Nothing

instance CheckRole 'EU where
  type RoleType 'EU = Region
  checkRole SEU = Just Proof
  checkRole _ = Nothing

instance CheckRole 'APAC where
  type RoleType 'APAC = Region
  checkRole SAPAC = Just Proof
  checkRole _ = Nothing

data RegionAuth (r :: Region) = RegionAuth {regionAuthTenant :: String}

type instance AuthServerData (AuthProtect "region-auth") = SomeRole RegionAuth

parseRegion :: Request -> Maybe (SomeRole RegionAuth)
parseRegion req = case lookup "X-Region" (requestHeaders req) of
  Just "us" -> Just (SomeRole SUS (RegionAuth "acme-us"))
  Just "eu" -> Just (SomeRole SEU (RegionAuth "acme-eu"))
  Just "apac" -> Just (SomeRole SAPAC (RegionAuth "acme-apac"))
  _ -> Nothing

regionAuthHandler :: AuthHandler Request (SomeRole RegionAuth)
regionAuthHandler = mkAuthHandler $ maybe (throwError err401) pure . parseRegion

gdprExport :: Proof 'EU r -> RegionAuth r -> String
gdprExport _proof auth = "GDPR export for " <> regionAuthTenant auth

type USAPI = RequireRole "region-auth" 'US :> "us" :> Get '[JSON] String

type EUAPI = RequireRole "region-auth" 'EU :> "eu" :> Get '[JSON] String

type APACAPI = RequireRole "region-auth" 'APAC :> "apac" :> Get '[JSON] String

type RegionAPI = USAPI :<|> EUAPI :<|> APACAPI

regionServer :: Server RegionAPI
regionServer = usH :<|> euH :<|> apacH
  where
    usH :: Satisfies 'US RegionAuth -> Handler String
    usH _ = pure "us ok"

    euH :: Satisfies 'EU RegionAuth -> Handler String
    euH (Satisfies proof auth) = pure (gdprExport proof auth)

    apacH :: Satisfies 'APAC RegionAuth -> Handler String
    apacH _ = pure "apac ok"

regionApp :: IO Application
regionApp = pure $ serveWithContext (Proxy @RegionAPI) (regionAuthHandler :. EmptyContext) regionServer

--------------------------------------------------------------------------------
-- Spec

hdr :: HeaderName -> ByteString -> [Header]
hdr name val = [(name, val), (hAccept, "application/json")]

roleReq :: ByteString -> ByteString -> WaiSession st SResponse
roleReq r path = request "GET" path (hdr "X-Role" r) ""

regionReq :: ByteString -> ByteString -> WaiSession st SResponse
regionReq r path = request "GET" path (hdr "X-Region" r) ""

spec :: Spec
spec = do
  describe "RequireRole" $ do
    -- Role x Route matrix (3 roles x 3 routes + unauthenticated = 12 cases)
    --
    --              | /viewer (Viewer) | /editor (Editor) | /admin (Admin)
    -- -------------|------------------|------------------|---------------
    -- Viewer       |       200        |       403        |      403
    -- Editor       |       200        |       200        |      403
    -- Admin        |       200        |       200        |      200
    -- No auth      |       401        |       401        |      401

    with roleApp $ do
      describe "hierarchical: /viewer (requires Viewer)" $ do
        it "Viewer -> 200" $ roleReq "viewer" "/viewer" `shouldRespondWith` 200
        it "Editor -> 200" $ roleReq "editor" "/viewer" `shouldRespondWith` 200
        it "Admin  -> 200" $ roleReq "admin" "/viewer" `shouldRespondWith` 200
        it "no auth -> 401" $ get "/viewer" `shouldRespondWith` 401

      describe "hierarchical: /editor (requires Editor)" $ do
        it "Viewer -> 403" $ roleReq "viewer" "/editor" `shouldRespondWith` 403
        it "Editor -> 200" $ roleReq "editor" "/editor" `shouldRespondWith` 200
        it "Admin  -> 200" $ roleReq "admin" "/editor" `shouldRespondWith` 200
        it "no auth -> 401" $ get "/editor" `shouldRespondWith` 401

      describe "hierarchical: /admin (requires Admin)" $ do
        it "Viewer -> 403" $ roleReq "viewer" "/admin" `shouldRespondWith` 403
        it "Editor -> 403" $ roleReq "editor" "/admin" `shouldRespondWith` 403
        it "Admin  -> 200, ban proof flows through" $
          roleReq "admin" "/admin" `shouldRespondWith` "\"banned by Sandy\"" {matchStatus = 200}
        it "no auth -> 401" $ get "/admin" `shouldRespondWith` 401

    with fallthroughApp $ do
      describe "same path, role-based fallthrough" $ do
        it "Admin  -> admin panel" $
          roleReq "admin" "/panel" `shouldRespondWith` "\"admin panel\"" {matchStatus = 200}
        it "Editor -> editor panel (falls through Admin)" $
          roleReq "editor" "/panel" `shouldRespondWith` "\"editor panel\"" {matchStatus = 200}
        it "Viewer -> viewer panel (falls through Admin, Editor)" $
          roleReq "viewer" "/panel" `shouldRespondWith` "\"viewer panel\"" {matchStatus = 200}
        it "no auth -> 401 (auth failure is fatal)" $ get "/panel" `shouldRespondWith` 401

    with anonApp $ do
      describe "public route behind RequireRole is unreachable" $ do
        it "no auth -> 401, not the public route" $ get "/panel" `shouldRespondWith` 401
        it "Viewer -> viewer panel (public route is dead code)" $
          roleReq "viewer" "/panel" `shouldRespondWith` "\"viewer panel\"" {matchStatus = 200}

    describe "auth handler invocation count" $ do
      it "Admin matches first alternative: auth runs 1 time" $ do
        counter <- newIORef 0
        app <- countingApp counter
        flip runWaiSession app $
          request "GET" "/panel" [("X-Role", "admin"), (hAccept, "application/json")] "" `shouldRespondWith` 200
        readIORef counter `shouldReturn` 1

      it "Editor falls through 1 alternative: auth runs 2 times" $ do
        counter <- newIORef 0
        app <- countingApp counter
        flip runWaiSession app $
          request "GET" "/panel" [("X-Role", "editor"), (hAccept, "application/json")] "" `shouldRespondWith` 200
        readIORef counter `shouldReturn` 2

      it "Viewer falls through 2 alternatives: auth runs 3 times" $ do
        counter <- newIORef 0
        app <- countingApp counter
        flip runWaiSession app $
          request "GET" "/panel" [("X-Role", "viewer"), (hAccept, "application/json")] "" `shouldRespondWith` 200
        readIORef counter `shouldReturn` 3

    -- Flat exact-match region matrix (equality, not hierarchy or membership)
    --          | /us | /eu | /apac
    -- us       | 200 | 403 | 403
    -- eu       | 403 | 200 | 403
    -- apac     | 403 | 403 | 200
    -- No auth  | 401 | 401 | 401
    with regionApp $ do
      describe "exact-match: US serves only /us" $ do
        it "/us    -> 200" $ regionReq "us" "/us" `shouldRespondWith` 200
        it "/eu    -> 403" $ regionReq "us" "/eu" `shouldRespondWith` 403
        it "/apac  -> 403" $ regionReq "us" "/apac" `shouldRespondWith` 403

      describe "exact-match: EU serves only /eu" $ do
        it "/eu    -> 200, GDPR proof flows through" $
          regionReq "eu" "/eu" `shouldRespondWith` "\"GDPR export for acme-eu\"" {matchStatus = 200}
        it "/us    -> 403" $ regionReq "eu" "/us" `shouldRespondWith` 403
        it "/apac  -> 403" $ regionReq "eu" "/apac" `shouldRespondWith` 403

      describe "exact-match: APAC serves only /apac" $ do
        it "/apac  -> 200" $ regionReq "apac" "/apac" `shouldRespondWith` 200
        it "/us    -> 403" $ regionReq "apac" "/us" `shouldRespondWith` 403

      it "no auth -> 401" $ get "/us" `shouldRespondWith` 401
