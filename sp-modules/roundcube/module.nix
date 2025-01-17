{ config, lib, pkgs, ... }:
let
  domain = config.selfprivacy.domain;
  cfg = config.selfprivacy.modules.roundcube;
  is-auth-enabled = config.selfprivacy.modules.auth.enable;
  auth-passthru = config.passthru.selfprivacy.auth;
  auth-fqdn = auth-passthru.auth-fqdn;
  oauth-client-id = "roundcube";
  roundcube-group = "roundcube";
  kanidmExecStartPreScriptRoot = pkgs.writeShellScript
    "${oauth-client-id}-kanidm-ExecStartPre-root-script.sh"
    ''
      # set-group-ID bit allows for kanidm user to create files,
      mkdir -p -v --mode=u+rwx,g+rs,g-w,o-rwx /run/keys/${oauth-client-id}
      chown kanidm:${roundcube-group} /run/keys/${oauth-client-id}
    '';
  kanidm-oauth-client-secret-fp =
    "/run/keys/${oauth-client-id}/kanidm-oauth-client-secret";
  kanidmExecStartPreScript = pkgs.writeShellScript
    "${oauth-client-id}-kanidm-ExecStartPre-script.sh" ''
    set -o xtrace
    [ -f "${kanidm-oauth-client-secret-fp}" ] || \
      "${lib.getExe pkgs.openssl}" rand -base64 -out "${kanidm-oauth-client-secret-fp}" 32
  '';
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
        $config['smtp_host'] = "tls://${config.mailserver.fqdn}";
        $config['smtp_user'] = "%u";
        $config['smtp_pass'] = "%p";
      '' + lib.strings.optionalString is-auth-enabled ''
        $config['oauth_provider'] = 'generic';
        $config['oauth_provider_name'] = '${auth-passthru.oauth2-provider-name}';
        $config['oauth_client_id'] = '${oauth-client-id}';
        $config['oauth_client_secret'] = "$(<${kanidm-oauth-client-secret-fp})";
        $config['oauth_auth_uri'] = 'https://${auth-fqdn}/ui/oauth2';
        $config['oauth_token_uri'] = 'https://${auth-fqdn}/oauth2/token';
        $config['oauth_identity_uri'] = 'https://${auth-fqdn}/oauth2/openid/${oauth-client-id}/userinfo';
        $config['oauth_scope'] = 'email profile openid'; # FIXME
        $config['oauth_auth_parameters'] = [];
        $config['oauth_identity_fields'] = ['email'];
        $config['oauth_login_redirect'] = true;
        $config['auto_create_user'] = true;
        $config['oauth_verify_peer'] = false; # FIXME
        # $config['oauth_pkce'] = 'S256'; # FIXME
      '';
    };

    services.nginx.virtualHosts."${cfg.subdomain}.${domain}" = {
      forceSSL = true;
      useACMEHost = domain;
      enableACME = false;
    };

    systemd.slices.roundcube.description = "Roundcube service slice";

    systemd.services.kanidm = lib.mkIf is-auth-enabled {
      serviceConfig.ExecStartPre = lib.mkAfter [
        ("-+" + kanidmExecStartPreScriptRoot)
        ("-" + kanidmExecStartPreScript)
      ];
      requires = [ auth-passthru.oauth2-systemd-service ];
    };

    services.kanidm.provision = lib.mkIf is-auth-enabled {
      groups = {
        "sp.roundcube.admins".members = [ "sp.admins" ];
        "sp.roundcube.users".members = [ "sp.roundcube.admins" ];
      };
      systems.oauth2.roundcube = {
        displayName = "Roundcube";
        originUrl = "https://${cfg.subdomain}.${domain}/index.php/login/oauth";
        originLanding = "https://${cfg.subdomain}.${domain}/";
        basicSecretFile = kanidm-oauth-client-secret-fp;
        # when true, name is passed to a service instead of name@domain
        preferShortUsername = false;
        allowInsecureClientDisablePkce = true; # FIXME is it needed?
        scopeMaps = {
          "sp.roundcube.users" = [
            "email"
            "openid"
            "profile"
          ];
        };
        removeOrphanedClaimMaps = true;
      };
    };
  };
}
