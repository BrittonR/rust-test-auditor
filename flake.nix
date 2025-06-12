{
  description = "rust-test-auditor - A tool to audit test suites for common anti-patterns";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nixpkgs.url = "nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ rust-overlay.overlays.default ];
        pkgs = import nixpkgs { inherit system overlays; };
        
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" ];
        };
        
        nativeBuildInputs = with pkgs; [
          rustToolchain
          pkg-config
        ];
        
        buildInputs = with pkgs; [
          openssl
        ];
      in {
        defaultPackage = pkgs.rustPlatform.buildRustPackage {
          pname = "rust-test-auditor";
          version = "0.1.0";
          
          src = ./.;
          
          cargoLock = {
            lockFile = ./Cargo.lock;
          };
          
          nativeBuildInputs = nativeBuildInputs;
          buildInputs = buildInputs;
        };
        
        devShell = pkgs.mkShell {
          nativeBuildInputs = nativeBuildInputs ++ (with pkgs; [
            rust-analyzer
            cargo-watch
            cargo-edit
          ]);
          
          buildInputs = buildInputs;
          
          RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
        };
      }
    );
}
