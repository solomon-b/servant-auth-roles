{-# OPTIONS_GHC -Wno-deferred-type-errors #-}
{-# OPTIONS_GHC -Wno-orphans -Wno-unused-top-binds -Wno-missing-signatures #-}
{-# OPTIONS_GHC -fdefer-type-errors #-}

-- | Fixture for the "forgot to run a deriver" regression test. Compiled with
-- @-fdefer-type-errors@ so the deliberately-missing 'Decidable' instance becomes
-- a runtime 'Control.Exception.TypeError' the spec can catch and inspect,
-- instead of a compile error that would fail the build.
module Servant.Auth.RolesErrorFixture (underivedDecidable, escalations) where

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

-- Each subroutine forces its own Atleast dictionary with atleastWitness.
-- Without that the deferred error is never demanded — an Atleast dictionary is
-- otherwise empty, so nothing projects from it — and every escalation below
-- would appear to succeed at runtime even while the compiler was correctly
-- rejecting it. The guard would then pass no matter what.
midOnly :: forall r. (IsAtleastMid r) => RankAuth r -> String
midOnly (RankAuth who) =
  atleastWitness (Proxy @'Mid) (Proxy @r) `seq` ("mid by " <> who)

highOnly :: forall r. (IsAtleastHigh r) => RankAuth r -> String
highOnly (RankAuth who) =
  atleastWitness (Proxy @'High) (Proxy @r) `seq` ("high by " <> who)

-- Run a gated subroutine behind a genuine proof for that gate (decideRole at
-- gate <= gate always succeeds); only the requirement asked for is too strong.
-- Written out per gate rather than shared through one kind-polymorphic helper:
-- such a helper picks up deferred errors of its own, and a spec that only
-- checked "something threw" would then pass on an unrelated kind mismatch while
-- the hierarchy silently leaked.
atLow :: (Satisfies 'Low RankAuth -> String) -> String
atLow body = case decideRole (sing @'Low) (sing @'Low) of
  Just proof -> body (Satisfies proof (RankAuth "mallory"))
  Nothing -> "unreachable: a role always satisfies itself"

atMid :: (Satisfies 'Mid RankAuth -> String) -> String
atMid body = case decideRole (sing @'Mid) (sing @'Mid) of
  Just proof -> body (Satisfies proof (RankAuth "mallory"))
  Nothing -> "unreachable: a role always satisfies itself"

-- | The three upward reaches in @Low < Mid < High@. Each must be rejected: a
-- gate's proof discharges its own rung and every rung below, never one above.
-- Each entry is @(label, alias the error must name, the offending call)@ — the
-- spec asserts the message, so an unrelated deferred error cannot pass for a
-- working hierarchy.
escalations :: [(String, String, String)]
escalations =
  [ ("Low -> Mid", "IsAtleastMid r", atLow (\(Satisfies RankProof a) -> midOnly a)),
    ("Low -> High", "IsAtleastHigh r", atLow (\(Satisfies RankProof a) -> highOnly a)),
    ("Mid -> High", "IsAtleastHigh r", atMid (\(Satisfies RankProof a) -> highOnly a))
  ]
