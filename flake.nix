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

      checks = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          hp = haskellPackagesFor system;
          ghc = hp.ghcWithPackages (ps: [ ps.servant-auth-roles ]);
        in
        {
          # The package build runs the test suite.
          servant-auth-roles = hp.servant-auth-roles;

          # Each file in test/compile-fail must fail to compile, with an error
          # that contains the text on its "-- EXPECT:" line. The text check
          # stops an unrelated error from passing as a rejection.
          compile-fail = pkgs.runCommand "servant-auth-roles-compile-fail"
            { nativeBuildInputs = [ ghc ]; } ''
            status=0
            for f in ${./test/compile-fail}/*.hs; do
              name=$(basename "$f")
              expect=$(sed -n 's/^-- EXPECT: //p' "$f")
              if [ -z "$expect" ]; then
                echo "FAIL $name: no -- EXPECT: line"
                status=1
              elif ghc -outputdir "$TMPDIR/$name" "$f" > "$TMPDIR/log" 2>&1; then
                echo "FAIL $name: compiled, but an error was expected"
                status=1
              elif grep -qF -- "$expect" "$TMPDIR/log"; then
                echo "ok   $name"
              else
                echo "FAIL $name: the error does not contain '$expect'"
                cat "$TMPDIR/log"
                status=1
              fi
            done
            [ "$status" -eq 0 ] && touch "$out"
            exit "$status"
          '';
        });

      devShells = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          hp = haskellPackagesFor system;
        in
        {
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
