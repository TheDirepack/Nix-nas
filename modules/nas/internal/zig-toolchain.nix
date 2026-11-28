{ pkgs }:
# nixpkgs 26.05 ships Zig up to 0.16.0; the KeePass tools target 0.17.1, so
# pin the official static release tarball by hash. Bump together with
# `minimum_zig_version` in zig/build.zig.zon and docs/development/dependencies.md.
assert pkgs.stdenv.hostPlatform.system == "x86_64-linux";
pkgs.stdenvNoCC.mkDerivation rec {
  pname = "zig";
  version = "0.17.1";
  src = pkgs.fetchurl {
    url = "https://ziglang.org/download/${version}/zig-x86_64-linux-${version}.tar.xz";
    hash = "sha256-NYGGPjy8/Q/ODvxoLOfp6T2pZmipd3kdNWom0qfpsXo=";
  };
  dontConfigure = true;
  dontBuild = true;
  # The release is a static executable plus its standard library sources.
  dontFixup = true;
  installPhase = ''
    runHook preInstall
    mkdir -p $out/bin $out/libexec/zig
    cp -r zig lib $out/libexec/zig/
    ln -s $out/libexec/zig/zig $out/bin/zig
    runHook postInstall
  '';
  meta = {
    description = "Zig ${version} toolchain (official static release)";
    homepage = "https://ziglang.org";
    platforms = [ "x86_64-linux" ];
    mainProgram = "zig";
  };
}
