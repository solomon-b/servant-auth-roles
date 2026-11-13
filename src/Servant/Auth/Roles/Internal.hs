-- | The seal on the constraint classes. This module is in @other-modules@, so
-- downstream code cannot import it.
module Servant.Auth.Roles.Internal
  ( ProvenByGate,
  )
where

--------------------------------------------------------------------------------

-- | The superclass of 'Servant.Auth.Roles.Member' and
-- 'Servant.Auth.Roles.Atleast'. An instance of either class compiles only when
-- GHC can solve this superclass. Downstream code cannot name it, so it cannot
-- write an instance that forges the evidence.
--
-- 'Servant.Auth.Roles.TH.deriveOrdRole' can still emit instances. A splice
-- refers to this class by its original name, and GHC does not check export
-- lists for such names.
--
-- The name shows in the error that a forged instance gets, so it tells the
-- reader where real evidence comes from.
class ProvenByGate (x :: k) (y :: j)
