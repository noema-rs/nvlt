{
  description = "nvlt — age-based secret manager CLI";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      forAllSystems =
        f: nixpkgs.lib.genAttrs systems (
          system:
          f {
            inherit system;
            pkgs = import nixpkgs {
              inherit system;
              overlays = [ ];
            };
          }
        );

      mkNvlt = pkgs: pkgs.callPackage ./package.nix { };

      packages = forAllSystems (
        { pkgs, ... }:
        let
          nvlt = mkNvlt pkgs;
        in
        {
          default = nvlt;
          inherit nvlt;
        }
      );
    in
    {
      inherit packages;

      checks = packages;

      apps = forAllSystems (
        { system, ... }:
        {
          default = {
            type = "app";
            program = "${self.packages.${system}.default}/bin/nvlt";
          };
        }
      );

      devShells = forAllSystems (
        { pkgs, ... }:
        {
          default = pkgs.mkShellNoCC {
            inputsFrom = [ (mkNvlt pkgs) ];

            packages = with pkgs; [
              rustc
              cargo
              rust-analyzer
              rustfmt
              clippy
              cargo-watch
              cargo-edit
            ];

            env.RUST_BACKTRACE = "1";

            shellHook = ''
              echo "Rust dev shell ready"
            '';
          };
        }
      );

      overlays.default = final: prev: {
        nvlt = final.callPackage ./package.nix { };
      };

      formatter = forAllSystems ({ pkgs, ... }: pkgs.nixfmt-rfc-style);
    };
}
