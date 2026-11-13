-- EXPECT: ProvenByGate
-- A catch-all instance must not lift every role to the top of a derived
-- hierarchy.
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

module ForgeAtleast where

import Servant.Auth.Roles.TH

data Rank = Low | Mid | High

$(deriveOrdRole ''Rank)

instance {-# INCOHERENT #-} Atleast 'High r
