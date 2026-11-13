-- EXPECT: ProvenByGate
-- An instance that assumes itself must not forge a hierarchy step.
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE UndecidableInstances #-}

module ForgeAtleastLoop where

import Servant.Auth.Roles (Atleast)

data Rank = Low | High

instance (Atleast 'High r) => Atleast 'High r
