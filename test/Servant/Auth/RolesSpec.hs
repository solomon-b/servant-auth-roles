
{-# OPTIONS_GHC -Wno-orphans #-}

module Servant.Auth.RolesSpec (spec) where

import Servant.Auth.Roles (CheckRole (..), HasRole (..), Proxy (..), RequireRole, Satisfies (Satisfies), Proof)
import Control.Monad.Except (throwError)
import Control.Monad.IO.Class (liftIO)
import Data.ByteString (ByteString)
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

instance CheckRole 'Viewer where
  type RoleType 'Viewer = UserRole
  checkRole _ role = role >= Viewer

instance CheckRole 'Editor where
  type RoleType 'Editor = UserRole
  checkRole _ role = role >= Editor

instance CheckRole 'Admin where
  type RoleType 'Admin = UserRole
  checkRole _ role = role >= Admin

data RoleAuth = RoleAuth {roleAuthRole :: UserRole, roleAuthName :: String}
  deriving (Show)

instance HasRole RoleAuth UserRole where
  getRole = roleAuthRole

type instance AuthServerData (AuthProtect "role-auth") = RoleAuth

parseRole :: Request -> Maybe RoleAuth
parseRole req = case lookup "X-Role" (requestHeaders req) of
  Just "viewer" -> pure (RoleAuth Viewer "Reed")
  Just "editor" -> pure (RoleAuth Editor "Lyxia")
  Just "admin" -> pure (RoleAuth Admin "Sandy")
  _ -> Nothing

-- | Reads the "X-Role" header to determine the user's role.
-- Missing header -> 401. Values: "viewer", "editor", "admin".
roleAuthHandler :: AuthHandler Request RoleAuth
roleAuthHandler = mkAuthHandler $ \req ->
  maybe (throwError err401) pure (parseRole req)

banUser :: Proof 'Admin -> RoleAuth -> String
banUser _prof auth = "banned by " <> roleAuthName auth

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
    editorHandler (Satisfies _proof auth) = pure $ "editor: " <> show (roleAuthRole auth)

    viewerHandler :: Satisfies 'Viewer RoleAuth -> Handler String
    viewerHandler (Satisfies _proof auth) = pure $ "viewer: " <> show (roleAuthRole auth)

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
countingAuthHandler :: IORef Int -> AuthHandler Request RoleAuth
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
    panelAdmin :: Satisfies prf RoleAuth -> Handler String
    panelAdmin _ = pure "admin panel"

    panelEditor :: Satisfies prf RoleAuth -> Handler String
    panelEditor _ = pure "editor panel"

    panelViewer :: Satisfies prf RoleAuth -> Handler String
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
-- Scheme 2: flat, non-hierarchical roles (exact match via Eq)

data Region = US | EU | APAC
  deriving (Eq, Ord, Show)

instance CheckRole 'US where
  type RoleType 'US = Region
  checkRole _ role = role == US

instance CheckRole 'EU where
  type RoleType 'EU = Region
  checkRole _ role = role == EU

instance CheckRole 'APAC where
  type RoleType 'APAC = Region
  checkRole _ role = role == APAC

data RegionAuth = RegionAuth {regionAuthRegion :: Region, regionAuthTenant :: String}

instance HasRole RegionAuth Region where
  getRole = regionAuthRegion

type instance AuthServerData (AuthProtect "region-auth") = RegionAuth

parseRegion :: Request -> Maybe RegionAuth
parseRegion req = case lookup "X-Region" (requestHeaders req) of
  Just "us" -> Just (RegionAuth US "acme-us")
  Just "eu" -> Just (RegionAuth EU "acme-eu")
  Just "apac" -> Just (RegionAuth APAC "acme-apac")
  _ -> Nothing

regionAuthHandler :: AuthHandler Request RegionAuth
regionAuthHandler = mkAuthHandler $ maybe (throwError err401) pure . parseRegion

gdprExport :: Proof 'EU -> RegionAuth -> String
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
