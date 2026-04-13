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

      # Helper to generate the NIX_CONFIG value that loads the plugin.
      # Use in a devShell:
      #
      #   pkgs.mkShell {
      #     NIX_CONFIG = inputs'.mini-agenix.lib.nixConfig;
      #   }
      #
      # The plugin MUST be loaded from a devShell (or equivalent) so that
      # the nix binary and the plugin are always built from the same nixpkgs.
      # Do NOT use nix.settings.plugin-files in NixOS configurations — it
      # forces every nix invocation on the system to load the plugin,
      # including nix-env during boot loader installation, which breaks
      # whenever the nix version and plugin version diverge across generations.
      lib = forAllSystems (
        pkgs:
        let
          plugin = self.packages.${pkgs.stdenv.hostPlatform.system}.mini-agenix;
        in
        {
          nixConfig = "plugin-files = ${plugin}/lib/libmini_agenix.so";
        }
      );

      checks = forAllSystems (pkgs: {
        build = self.packages.${pkgs.stdenv.hostPlatform.system}.mini-agenix;

        plugin = import ./tests/plugin.nix {
          inherit pkgs;
          mini-agenix = self.packages.${pkgs.stdenv.hostPlatform.system}.mini-agenix;
        };
      });
    };
}
