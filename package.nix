{
  lib,
  rustPlatform,
}:

rustPlatform.buildRustPackage rec {
  pname = "nvlt";
  version = "0.1.51";

  src = lib.cleanSource ./.;

  cargoLock = {
    lockFile = ./Cargo.lock;
  };

  cargoBuildFlags = [ "-p" "cli" ];

  meta = with lib; {
    description = "Vault secret manager CLI";
    homepage = "https://github.com/noema-rs/vault";
    license = licenses.mit;
    mainProgram = "nvlt";
    platforms = platforms.linux;
  };
}
