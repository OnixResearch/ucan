{
  description = "ucan — Rust project built with Crane";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
    # Keep the sibling dependency portable across checkouts. Current Nix
    # warns on relative git+file inputs, but this avoids a machine-specific
    # absolute path while preserving the existing ../verified-logic contract.
    verified-logic-src = {
      url = "git+file:../verified-logic";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, crane, rust-overlay, flake-utils, verified-logic-src, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # Common source filtering
        ucanSrc = craneLib.cleanCargoSource ./.;
        verifiedLogicSrc = craneLib.cleanCargoSource verified-logic-src;
        src = pkgs.runCommand "ucan-combined-source" {} ''
          mkdir -p $out/verified-logic
          cp -R ${ucanSrc}/. $out/
          cp -R ${verifiedLogicSrc}/. $out/verified-logic/
          chmod -R u+w $out $out/verified-logic
        '';

        # Common build inputs
        nativeBuildInputs = with pkgs; [
          pkg-config
          clang
          mold
        ];

        buildInputs = with pkgs; [
          openssl
        ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
          pkgs.darwin.apple_sdk.frameworks.Security
          pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
        ];

        commonArgs = {
          inherit src nativeBuildInputs buildInputs;
          cargoToml = ./Cargo.toml;
          cargoLock = ./Cargo.lock;
          postPatch = ''
            ln -sfn "$PWD/verified-logic" ../verified-logic
          '';
        };

        # Build just the cargo dependencies for caching
        cargoArtifacts = craneLib.buildDepsOnly (commonArgs);

        # Build the actual package
        ucan = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
        });
      in
      {
        packages = {
          default = ucan;
          ucan = ucan;
        };

        checks = {
          inherit ucan;

          # Run tests with nextest
          nextest = craneLib.cargoNextest (commonArgs // {
            inherit cargoArtifacts;
            partitions = 1;
            partitionType = "count";
          });

          # Clippy lints
          clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- -D warnings";
          });

          # Format check
          fmt = craneLib.cargoFmt (commonArgs);
        };

        devShells.default = craneLib.devShell {
          inherit buildInputs;

          packages = with pkgs; [
            cargo-nextest
            cargo-watch
            rust-analyzer
          ];

          # Ensure the nightly toolchain is available and the verified-logic
          # sibling dependency is present in the Nix source tree.
          inputsFrom = [ ucan ];
        };
      }
    );
}
