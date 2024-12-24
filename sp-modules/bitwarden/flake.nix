{
  description = "PoC SP module for Bitwarden password management solution";

  outputs = { self }: {
    nixosModules.default = _:
      { imports = [ ./module.nix ./cleanup-module.nix ]; };
    configPathsNeeded =
      builtins.fromJSON (builtins.readFile ./config-paths-needed.json);
    meta = { lib, ... }: {
      spModuleVersion = 1;
      id = "bitwarden";
      name = "Bitwarden";
      description = "Bitwarden is a password manager.";
      svgIcon = builtins.readFile ./icon.svg;
      isMovable = true;
      isRequired = false;
      backupDescription = "Password database, encryption certificate and attachments.";
      systemdServices = [
        "vaultwarden.service"
      ];
      user = "vaultwarden";
      folders = [
        "/var/lib/bitwarden"
        "/var/lib/bitwarden_rs"
      ];
      license = [
        lib.licenses.agpl3Only
      ];
      homepage = "https://github.com/dani-garcia/vaultwarden";
      sourcePage = "https://github.com/dani-garcia/vaultwarden";
      supportLevel = "normal";
    };
  };
}
