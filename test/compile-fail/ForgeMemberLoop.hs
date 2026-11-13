-- EXPECT: ProvenByGate
-- An instance that assumes itself must not forge membership.
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE UndecidableInstances #-}

module ForgeMemberLoop where

import Servant.Auth.Roles (Member)

data Permission = PermRead | PermManage

instance (Member 'PermManage ps) => Member 'PermManage ps
