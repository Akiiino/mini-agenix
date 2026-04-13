{
  description = "Evaluation-time age decryption for Nix";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    { self, nixpkgs }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems =
        f: nixpkgs.lib.genAttrs supportedSystems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: {
        mini-agenix = pkgs.callPackage ./package.nix { };
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.mini-agenix;
      });

      nixosModules = {
        mini-agenix =
          {
            config,
            lib,
            pkgs,
            ...
          }:

          let
            cfg = config.mini-agenix;
          in
          {
            options.mini-agenix = {
              enable = lib.mkEnableOption "mini-agenix evaluation-time secret decryption plugin";
              package = lib.mkPackageOption self.packages.${pkgs.stdenv.hostPlatform.system} "mini-agenix" { };
            };

            config = lib.mkIf cfg.enable {
              nix.settings.plugin-files = [ "${cfg.package}/lib/libmini_agenix.so" ];
            };
          };
        default = self.nixosModules.mini-agenix;
      };

      checks = forAllSystems (pkgs: {
        build = self.packages.${pkgs.stdenv.hostPlatform.system}.mini-agenix;

        plugin = import ./tests/plugin.nix {
          inherit pkgs;
          mini-agenix = self.packages.${pkgs.stdenv.hostPlatform.system}.mini-agenix;
        };
      });
    };
}
