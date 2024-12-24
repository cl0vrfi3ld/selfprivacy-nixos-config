{
  description = "PoC SP module for Prometheus-based monitoring";

  outputs = { self }: {
    nixosModules.default = import ./module.nix;
    configPathsNeeded =
      builtins.fromJSON (builtins.readFile ./config-paths-needed.json);
    meta = { lib, ... }: {
      spModuleManifestVersion = 1;
      id = "monitoring";
      name = "Prometheus";
      description = "Prometheus is used for resource monitoring and alerts.";
      svgIcon = builtins.readFile ./icon.svg;
      isMovable = false;
      isRequired = true;
      canBeBackedUp = false;
      backupDescription = "Backups are not available for Prometheus.";
      systemdServices = [
        "prometheus.service"
      ];
      ownedFolders = [
        {
          path = "/var/lib/prometheus";
          owner = "prometheus";
          group = "prometheus";
        }
      ];
      license = [
        lib.licenses.asl20
      ];
      homepage = "https://prometheus.io/";
      sourcePage = "https://prometheus.io/";
      supportLevel = "normal";
    };
  };
}
