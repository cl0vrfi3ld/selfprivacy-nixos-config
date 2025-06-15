{
  description = "Flake description";

  outputs =
    { self }:
    {
      nixosModules.default = import ./module.nix;
      configPathsNeeded = builtins.fromJSON (builtins.readFile ./config-paths-needed.json);
      meta =
        { lib, ... }:
        {
          spModuleSchemaVersion = 1;
          id = "actual";
          name = "Actual Budget";
          description = "Actual Budget is a super fast and privacy-focused app for managing your finances.";
          svgIcon = builtins.readFile ./icon.svg;
          showUrl = true;
          primarySubdomain = "actual";
          isMovable = false;
          isRequired = false;
          canBeBackedUp = true;
          backupDescription = "Your budgets, settings, and account secrets (where applicable).";
          systemdServices = [
            "actual.service"
          ];
          user = "actual";
          group = "actual";
          folders = [
            "/var/lib/actual"
          ];

          license = [
            lib.licenses.mit
          ];
          homepage = "https://actualbudget.org/";
          sourcePage = "https://github.com/actualbudget/actual";
          # since this module hasn't been thoroughly tested, I'd advertise it as `experimental`, but is also a `community` class module
          supportLevel = "experimental";
        };
    };
}
