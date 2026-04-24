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

        # Build the actual package. Tests run in the explicit nextest check below;
        # Hegel integration tests need a writable Python/uv environment and are
        # exercised from the dev shell rather than the sandboxed package build.
        ucan = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          doCheck = false;
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
            cargoExtraArgs = "--locked -p ucan -p ucan-core --lib --examples";
          });

          # Clippy lints for workspace packages only; the vendored snapshot keeps upstream lint policy.
          clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            cargoExtraArgs = "--locked --no-deps -p ucan -p ucan-core";
            cargoClippyExtraArgs = "--all-targets -- -D warnings -A clippy::cargo-common-metadata";
          });

          # Format only workspace packages; keep the vendored verified-logic snapshot byte-for-byte.
          fmt = craneLib.cargoFmt (commonArgs // {
            cargoExtraArgs = "--manifest-path Cargo.toml -p ucan -p ucan-core";
          });
        };

        devShells.default = craneLib.devShell {
          inherit buildInputs;

          packages = with pkgs; [
            cargo-fuzz
            cargo-mutants
            cargo-nextest
            cargo-watch
            rust-analyzer
            uv
          ];

          # Ensure the nightly toolchain and vendored verified-logic source are
          # present in the same cleaned build tree used by the package.
          inputsFrom = [ ucan ];
        };
      }
    );
}
