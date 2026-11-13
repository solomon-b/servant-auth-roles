-- EXPECT: ProvenByGate
-- A bare instance must not forge membership.
{-# LANGUAGE DataKinds #-}

module ForgeMember where

import Servant.Auth.Roles (Member)

data Permission = PermRead | PermManage

instance Member 'PermManage ps
