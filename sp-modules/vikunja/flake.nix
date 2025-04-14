{
  description = "PoC SP module for Vikunja service";

  inputs = {
    nixpkgs-24-11.url = "github:NixOS/nixpkgs/nixos-24.11";
  };

  outputs = {nixpkgs-24-11, ...}: {
    nixosModules.default = import ./module.nix nixpkgs-24-11.legacyPackages.x86_64-linux;
    configPathsNeeded =
      builtins.fromJSON (builtins.readFile ./config-paths-needed.json);
    meta = {lib, ...}: {
      spModuleSchemaVersion = 1;
      id = "vikunja";
      name = "Vikunja";
      description = "Vikunja, the fluffy, open-source, self-hostable to-do app.";
      svgIcon = builtins.readFile ./icon.svg;
      isMovable = true;
      isRequired = false;
      backupDescription = "Tasks and attachments.";
      systemdServices = [
        "vikunja.service"
      ];
      folders = [
        "/var/lib/vikunja"
      ];
      postgreDatabases = [
        "vikunja"
      ];
      license = [
        lib.licenses.agpl3Plus
      ];
      homepage = "https://vikunja.io";
      sourcePage = "https://github.com/go-vikunja/vikunja";
      supportLevel = "normal";
      sso = {
        userGroup = "sp.vikunja.users";
      };
    };
  };
}
