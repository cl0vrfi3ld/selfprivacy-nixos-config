{
  description = "PoC SP module for Mumble conferences server";

  outputs = { self }: {
    nixosModules.default = import ./module.nix;
    configPathsNeeded =
      builtins.fromJSON (builtins.readFile ./config-paths-needed.json);
    meta = { lib, ... }: {
      spModuleManifestVersion = 1;
      id = "mumble";
      name = "Mumble";
      description = "Open Source, Low Latency, High Quality Voice Chat.";
      svgIcon = builtins.readFile ./icon.svg;
      showUrl = false;
      isMovable = true;
      isRequired = false;
      canBeBackedUp = true;
      backupDescription = "Mumble server data.";
      systemdServices = [
        "murmur.service"
      ];
      user = "murmur";
      group = "murmur";
      folders = [
        "/var/lib/murmur"
      ];
      license = [
        lib.licenses.bsd3
      ];
      homepage = "https://www.mumble.info";
      sourcePage = "https://github.com/mumble-voip/mumble";
      supportLevel = "normal";
    };
  };
}
