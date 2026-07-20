{-# OPTIONS_GHC -Wno-deferred-type-errors #-}
{-# OPTIONS_GHC -Wno-orphans -Wno-unused-top-binds -Wno-missing-signatures #-}
{-# OPTIONS_GHC -fdefer-type-errors #-}

-- | Fixture for the "forgot to run a deriver" regression test. Compiled with
-- @-fdefer-type-errors@ so the deliberately-missing 'Decidable' instance becomes
-- a runtime 'Control.Exception.TypeError' the spec can catch and inspect,
-- instead of a compile error that would fail the build.
module Servant.Auth.RolesErrorFixture (underivedDecidable, escalated) where

import Servant.Auth.Roles.TH

data Undrived = Foo | Bar

-- Singletons and ActualK are supplied by hand so the only thing missing is the
-- Decidable instance. This isolates our error from unrelated singletons errors.
$(genSingletons [''Undrived])

type instance ActualK (r :: Undrived) = Undrived

-- No deriveOrdRole/deriveEqRole/deriveMemberRole was run, so there is no Decidable
-- instance and the OVERLAPPABLE fallback's TypeError applies. Forcing this value
-- (which projects the missing dictionary) raises that error at runtime.
underivedDecidable :: ()
underivedDecidable = decideRole (sing @'Foo) (sing @'Foo) `seq` ()

--------------------------------------------------------------------------------
-- Privilege escalation guard.
--
-- deriveOrdRole makes a gate's proof weakening-closed: it discharges every
-- IsAtleast<Con> at or below the gate's own role. This fixture pins the other
-- half of that property — the chain must not run /upward/. A Mid gate has no
-- business calling a High-gated subroutine, and asking for one is a type error.
-- It lives here, deferred, because a compile error is what we want to assert.

data Rank = Low | Mid | High

$(deriveOrdRole ''Rank)

newtype RankAuth (r :: Rank) = RankAuth String

highOnly :: (IsAtleastHigh r) => RankAuth r -> String
highOnly (RankAuth who) = "escalated by " <> who

-- The Mid proof releases IsAtleastLow and IsAtleastMid, but not IsAtleastHigh,
-- so this call is rejected. Under -fdefer-type-errors it becomes the runtime
-- TypeError the spec forces.
escalate :: Satisfies 'Mid RankAuth -> String
escalate (Satisfies RankProof auth) = highOnly auth

escalated :: String
escalated = case decideRole (sing @'Mid) (sing @'Mid) of
  Just proof -> escalate (Satisfies proof (RankAuth "mallory"))
  Nothing -> "unreachable: Mid satisfies Mid"
