{
  lib,
  stdenv,
  pkg-config,
  nix,
  age,
}:

stdenv.mkDerivation {
  pname = "mini-agenix";
  version = "0.1.0";

  src = lib.cleanSource ./.;

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ nix ];

  buildPhase = ''
    runHook preBuild
    $CXX -shared -fPIC -std=c++20 -O2 \
      $(pkg-config --cflags nix-expr nix-store) \
      -DAGE_PATH='"${lib.getExe age}"' \
      -o libmini_agenix.so \
      plugin.cpp \
      $(pkg-config --libs nix-expr nix-store)
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    install -D -m 444 libmini_agenix.so $out/lib/libmini_agenix.so
    runHook postInstall
  '';

  meta = {
    description = "Nix plugin for evaluation-time age decryption";
    license = lib.licenses.unlicense;
    platforms = lib.platforms.linux;
  };
}
