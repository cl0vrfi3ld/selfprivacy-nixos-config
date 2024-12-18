{ config, lib, ... }:
let
  domain = config.selfprivacy.domain;
  cfg = config.selfprivacy.modules.roundcube;
in
{
  options.selfprivacy.modules.roundcube = {
    enable = (lib.mkOption {
      default = false;
      type = lib.types.bool;
      description = "Enable";
    }) // {
      meta = {
        type = "enable";
      };
    };
    subdomain = (lib.mkOption {
      default = "roundcube";
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
  };

  config = lib.mkIf cfg.enable {

    services.roundcube = {
      enable = true;
      # this is the url of the vhost, not necessarily the same as the fqdn of
      # the mailserver
      hostName = "${cfg.subdomain}.${config.selfprivacy.domain}";
      extraConfig = ''
        # starttls needed for authentication, so the fqdn required to match
        # the certificate
        $config['smtp_server'] = "tls://${config.mailserver.fqdn}";
        $config['smtp_user'] = "%u";
        $config['smtp_pass'] = "%p";
      '';
    };
    services.nginx.virtualHosts."${cfg.subdomain}.${domain}" = {
      forceSSL = true;
      useACMEHost = domain;
      enableACME = false;
    };
    systemd = {
      services = {
        phpfpm-roundcube.serviceConfig.Slice = lib.mkForce "roundcube.slice";
      };
      slices.roundcube = {
        description = "Roundcube service slice";
      };
    };
  };
}
