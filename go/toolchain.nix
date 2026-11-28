{ buildPackages, fetchurl, stdenvNoCC }:

stdenvNoCC.mkDerivation (finalAttrs: {
  pname = "go";
  version = "1.27.4";
  src = fetchurl {
    url = "https://go.dev/dl/go${finalAttrs.version}.src.tar.gz";
    hash = "sha256-c8+4VxrsDAEXdofbhxY9Rqog6XeWcncokaoXZU2aYJk=";
  };

  inherit (stdenvNoCC.hostPlatform.go) GOOS GOARCH;
  CGO_ENABLED = "0";
  GOROOT_BOOTSTRAP = "${buildPackages.go}/share/go";
  postPatch = "patchShebangs .";
  dontConfigure = true;
  buildPhase = ''
    runHook preBuild
    export GOCACHE="$TMPDIR/go-cache"
    (cd src && ./make.bash)
    runHook postBuild
  '';
  installPhase = ''
    runHook preInstall
    mkdir -p "$out/share/go" "$out/bin"
    cp -a bin pkg src lib misc api doc go.env VERSION "$out/share/go"
    ln -s "$out/share/go/bin/"* "$out/bin/"
    runHook postInstall
  '';
  meta.mainProgram = "go";
})
