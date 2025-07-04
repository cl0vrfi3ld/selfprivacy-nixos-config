{ config, lib, pkgs, ... }:
let
  secrets-filepath = "/etc/selfprivacy/secrets.json";
  backup-dir = "/var/lib/bitwarden/backup";
  cfg = sp.modules.bitwarden;
  inherit (import ./common.nix config) bitwarden-env sp;
in
{
  options.selfprivacy.modules.bitwarden = {
    enable = (lib.mkOption {
      default = false;
      type = lib.types.bool;
      description = "Enable Vaultwarden";
    }) // {
      meta = {
        type = "enable";
      };
    };
    location = (lib.mkOption {
      type = lib.types.str;
      description = "Vaultwarden location";
    }) // {
      meta = {
        type = "location";
      };
    };
    subdomain = (lib.mkOption {
      default = "password";
      type = lib.types.strMatching "[A-Za-z0-9][A-Za-z0-9\-]{0,61}[A-Za-z0-9]";
      description = "Subdomain";
    }) // {
      meta = {
        widget = "subdomain";
        type = "string";
        regex = "[A-Za-z0-9][A-Za-z0-9\-]{0,61}[A-Za-z0-9]";
        weight = 0;
      };
    };
    signupsAllowed = (lib.mkOption {
      default = true;
      type = lib.types.bool;
      description = "Allow new user signups";
    }) // {
      meta = {
        type = "bool";
        weight = 1;
      };
    };
    sendsAllowed = (lib.mkOption {
      default = true;
      type = lib.types.bool;
      description = "Allow users to use Bitwarden Send";
    }) // {
      meta = {
        type = "bool";
        weight = 2;
      };
    };
    emergencyAccessAllowed = (lib.mkOption {
      default = true;
      type = lib.types.bool;
      description = "Allow users to enable Emergency Access";
    }) // {
      meta = {
        type = "bool";
        weight = 3;
      };
    };
  };

  config = lib.mkIf config.selfprivacy.modules.bitwarden.enable {
    fileSystems = lib.mkIf sp.useBinds {
      "/var/lib/bitwarden" = {
        device = "/volumes/${cfg.location}/bitwarden";
        options = [
          "bind"
          "x-systemd.required-by=bitwarden-secrets.service"
          "x-systemd.required-by=backup-vaultwarden.service"
          "x-systemd.required-by=vaultwarden.service"
          "x-systemd.before=bitwarden-secrets.service"
          "x-systemd.before=backup-vaultwarden.service"
          "x-systemd.before=vaultwarden.service"
        ];
      };
      "/var/lib/bitwarden_rs" = {
        device = "/volumes/${cfg.location}/bitwarden_rs";
        options = [
          "bind"
          "x-systemd.required-by=bitwarden-secrets.service"
          "x-systemd.required-by=backup-vaultwarden.service"
          "x-systemd.required-by=vaultwarden.service"
          "x-systemd.before=bitwarden-secrets.service"
          "x-systemd.before=backup-vaultwarden.service"
          "x-systemd.before=vaultwarden.service"
        ];
      };
    };
    systemd.tmpfiles.rules = lib.mkIf sp.useBinds [
      "d /volumes/${cfg.location}/bitwarden/backup 0700 vaultwarden vaultwarden -"
    ];
    services.vaultwarden = {
      enable = true;
      dbBackend = "sqlite";
      backupDir = backup-dir;
      environmentFile = "${bitwarden-env}";
      config = {
        DOMAIN = "https://${cfg.subdomain}.${sp.domain}/";
        SIGNUPS_ALLOWED = cfg.signupsAllowed;
        ROCKET_PORT = 8222;
        SENDS_ALLOWED = cfg.sendsAllowed;
        EMERGENCY_ACCESS_ALLOWED = cfg.emergencyAccessAllowed;
      };
    };
    systemd = {
      services = {
        vaultwarden.serviceConfig.Slice = "bitwarden.slice";
        bitwarden-secrets = {
          before = [ "vaultwarden.service" ];
          requiredBy = [ "vaultwarden.service" ];
          serviceConfig.Type = "oneshot";
          path = with pkgs; [ coreutils jq ];
          script = ''
            set -o nounset

            token="$(jq -r '.bitwarden.adminToken' ${secrets-filepath})"
            if [ "$token" == "null" ]; then
                # If it's null, empty the contents of the file
                bitwarden_env=""
            else
                bitwarden_env="ADMIN_TOKEN=$token"
            fi

            install -C -m 0700 -o vaultwarden -g vaultwarden \
            -d /var/lib/bitwarden

            install -C -m 0600 -o vaultwarden -g vaultwarden -DT \
            <(printf "%s" "$bitwarden_env") ${bitwarden-env}
          '';
        };
      };
      slices.bitwarden = {
        description = "Bitwarden service slice";
      };
    };
    services.nginx.virtualHosts."${cfg.subdomain}.${sp.domain}" = {
      useACMEHost = sp.domain;
      forceSSL = true;
      extraConfig = ''
        add_header Strict-Transport-Security $hsts_header;
        #add_header Content-Security-Policy "script-src 'self'; object-src 'none'; base-uri 'none';" always;
        add_header 'Referrer-Policy' 'origin-when-cross-origin';
        add_header X-Frame-Options SAMEORIGIN;
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";
        proxy_cookie_path / "/; secure; HttpOnly; SameSite=strict";
      '';
      locations = {
        "/" = {
          proxyPass = "http://127.0.0.1:8222";
        };
      };
    };
    # NixOS upstream bug? Otherwise, backup-vaultwarden cannot find sqlite DB.
    systemd.services.backup-vaultwarden.unitConfig.ConditionPathExists =
      "/var/lib/bitwarden_rs/db.sqlite3";
  };
}
