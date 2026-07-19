{
  description = "Type-level role-based authorization combinators for Servant";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

      # Haskell package set for a given system with servant-auth-roles built
      # from the local cabal file via callCabal2nix.
      haskellPackagesFor = system:
        nixpkgs.legacyPackages.${system}.haskellPackages.override {
          overrides = hfinal: hprev: {
            servant-auth-roles =
              hfinal.callCabal2nix "servant-auth-roles" ./. { };
          };
        };
    in
    {
      packages = forAllSystems (system:
        let hp = haskellPackagesFor system;
        in {
          servant-auth-roles = hp.servant-auth-roles;
          default = hp.servant-auth-roles;
        });

      devShells = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          hp = haskellPackagesFor system;
        in {
          default = hp.shellFor {
            packages = ps: [ ps.servant-auth-roles ];
            withHoogle = true;
            nativeBuildInputs = [
              hp.cabal-install
              hp.haskell-language-server
              pkgs.just
              pkgs.nixpkgs-fmt
              pkgs.ormolu
            ];
          };
        });
    };
}
