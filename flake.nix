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
  };

  outputs = { self, nixpkgs, crane, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # Keep the vendored verified-logic crate inside the cleaned Cargo source.
        src = craneLib.cleanCargoSource ./.;

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

          # Ensure the nightly toolchain and vendored verified-logic source are
          # present in the same cleaned build tree used by the package.
          inputsFrom = [ ucan ];
        };
      }
    );
}
