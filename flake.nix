{
  description = "btz — a crawler for the Bitcoin peer-to-peer network";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    # Exact Zig releases, including the 0.16.0 this project pins.
    zig-overlay.url = "github:mitchellh/zig-overlay";
    zig-overlay.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    { self, nixpkgs, zig-overlay }:
    let
      # The event loop is io_uring, so Linux only.
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAll =
        f:
        nixpkgs.lib.genAttrs systems (
          system:
          f {
            inherit system;
            pkgs = nixpkgs.legacyPackages.${system};
            zig = zig-overlay.packages.${system}."0.16.0";
          }
        );
    in
    {
      devShells = forAll (
        { pkgs, zig, ... }:
        {
          default = pkgs.mkShell {
            # `zls` comes from nixpkgs; if it lags 0.16 it just prints a
            # version-mismatch warning, it does not break the shell.
            packages = [
              zig
              pkgs.zls
            ];
          };
        }
      );

      packages = forAll (
        { pkgs, zig, ... }:
        {
          default = pkgs.stdenv.mkDerivation {
            pname = "btz";
            version = "0.1.0";

            # Only the build inputs — keeps zig-out / .zig-cache / btz.log out
            # of the store path.
            src = pkgs.lib.fileset.toSource {
              root = ./.;
              fileset = pkgs.lib.fileset.unions [
                ./build.zig
                ./build.zig.zon
                ./src
              ];
            };

            nativeBuildInputs = [ zig ];
            dontConfigure = true;
            dontInstall = true;

            buildPhase = ''
              runHook preBuild
              export ZIG_GLOBAL_CACHE_DIR="$TMPDIR/zig-cache"
              zig build --release --prefix "$out"
              runHook postBuild
            '';

            meta = {
              description = "A crawler for the Bitcoin peer-to-peer network";
              mainProgram = "btz";
              license = nixpkgs.lib.licenses.mit;
              platforms = nixpkgs.lib.platforms.linux;
            };
          };
        }
      );

      apps = forAll (
        { system, ... }:
        {
          default = {
            type = "app";
            program = "${self.packages.${system}.default}/bin/btz";
          };
        }
      );

      formatter = forAll ({ pkgs, ... }: pkgs.nixfmt-rfc-style);
    };
}
