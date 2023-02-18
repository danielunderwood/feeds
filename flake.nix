{
  inputs = {
    naersk.url = "github:nix-community/naersk/master";
    utils.url = "github:numtide/flake-utils";
    nixpkgs-mozilla = {
      url = "github:mozilla/nixpkgs-mozilla";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, utils, naersk, nixpkgs-mozilla }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = (import nixpkgs) {
          inherit system;
          overlays = [ (import nixpkgs-mozilla) ];
        };
        naersk-lib = pkgs.callPackage naersk { };

        # Search for 'toolchain' on https://github.com/nix-community/naersk
        toolchain = (pkgs.rustChannelOf {
          rustToolchain = ./toolchain.toml;
          sha256 = "sha256-S4dA7ne2IpFHG+EnjXfogmqwGyDFSRWFnJ8cy4KZr1k=";
        }).rust;

        naersk' = pkgs.callPackage naersk {
          cargo = toolchain;
          rust = toolchain;
        };
      in
      {
        defaultPackage = naersk-lib.buildPackage ./.;
        devShell = with pkgs; mkShell {
          buildInputs = [
            cargo
            libiconv
            nixpkgs-fmt
            nodePackages.wrangler
            rustfmt
            pre-commit
            rustPackages.clippy
          ];
        };
      });
}
