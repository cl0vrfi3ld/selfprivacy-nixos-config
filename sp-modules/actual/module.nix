{
  config,
  lib,
  pkgs,
  ...
}:
let
  # Just for convinience, this module's config values
  sp = config.selfprivacy;
  cfg = sp.modules.actual;

  is-auth-enabled = cfg.enableSso && config.selfprivacy.sso.enable;
  oauthClientID = "actual";
  auth-passthru = config.selfprivacy.passthru.auth;
  oauth2-provider-name = auth-passthru.oauth2-provider-name;
  full-domain = "https://${cfg.subdomain}.${sp.domain}";
  redirect-uri = "${full-domain}/path/openid/callback";
  landing-uri = "${full-domain}/login";
  oauthDiscoveryURL = auth-passthru.oauth2-discovery-url oauthClientID;
  adminsGroup = "sp.${oauthClientID}.admins";
  usersGroup = "sp.${oauthClientID}.users";

  linuxUserOfService = "actual";
  linuxGroupOfService = "actual";

  oauthClientSecretFP = auth-passthru.mkOAuth2ClientSecretFP linuxGroupOfService;

in
{
  # Here go the options you expose to the user.
  options.selfprivacy.modules.actual = {
    # This is required and must always be named "enable"
    enable =
      (lib.mkOption {
        default = false;
        type = lib.types.bool;
        description = "Enable the Actual Budget server";
      })
      // {
        meta = {
          type = "enable";
        };
      };
    # This is required if your service stores data on disk
    location =
      (lib.mkOption {
        type = lib.types.str;
        description = "Data location";
      })
      // {
        meta = {
          type = "location";
        };
      };
    # This is required if your service needs a subdomain
    subdomain =
      (lib.mkOption {
        default = "actual";
        type = lib.types.strMatching "[A-Za-z0-9][A-Za-z0-9\-]{0,61}[A-Za-z0-9]";
        description = "Subdomain";
      })
      // {
        meta = {
          widget = "subdomain";
          type = "string";
          regex = "[A-Za-z0-9][A-Za-z0-9\-]{0,61}[A-Za-z0-9]";
          weight = 0;
        };
      };
    # Other options, that user sees directly.
    # Refer to Module options reference to learn more.
    enableSso =
      (lib.mkOption {
        default = false;
        type = lib.types.bool;
        description = "Enable Single Sign-On";
      })
      // {
        meta = {
          type = "bool";
          weight = 2;
        };
      };
    # signupsAllowed = (lib.mkOption {
    #   default = true;
    #   type = lib.types.bool;
    #   description = "Allow new user signups";
    # }) // {
    #   meta = {
    #     type = "bool";
    #     weight = 1;
    #   };
    # };
    # appName = (lib.mkOption {
    #   default = "SelfPrivacy Service";
    #   type = lib.types.str;
    #   description = "The name displayed in the web interface";
    # }) // {
    #   meta = {
    #     type = "string";
    #     weight = 2;
    #   };
    # };
    # defaultTheme = (lib.mkOption {
    #   default = "auto";
    #   type = lib.types.enum [
    #       "auto"
    #       "light"
    #       "dark"
    #   ];
    #   description = "Default theme";
    # }) // {
    #   meta = {
    #     type = "enum";
    #     options = [
    #       "auto"
    #       "light"
    #       "dark"
    #     ];
    #     weight = 3;
    #   };
    # };
  };

  # All your changes to the system must go to this config attrset.
  # It MUST use lib.mkIf with an enable option.
  # This makes sure your module only makes changes to the system
  # if the module is enabled.
  config = lib.mkIf cfg.enable (
    lib.mkMerge [
      {
        assertions = [
          {
            assertion = cfg.enableSso -> sp.sso.enable;
            message = "SSO cannot be enabled for Nextcloud when SSO is disabled globally.";
          }
        ];
        # If your service stores data on disk, you have to mount a folder
        # for this. useBinds is always true on modern SelfPrivacy installations
        # but we keep this mkIf to keep migration flow possible.
        fileSystems = lib.mkIf sp.useBinds {
          "/var/lib/actual" = {
            device = "/volumes/${cfg.location}/actual";
            # Make sure that your service does not start before folder mounts
            options = [
              "bind"
              "x-systemd.required-by=actual.service"
              "x-systemd.before=actual.service"
            ];
          };
        };
        # Your service configuration, varies heavily.
        # Refer to NixOS Options search.
        # You can use defined options here.
        services.actual = {
          enable = true;
          # openFirewall = true; # unneeded as we are using the built-in proxy server
          settings = {
            # ACTUAL_DATA_DIR = "/var/lib/actual";
            port = 5006;
            # hostname = "${cfg.subdomain}.${sp.domain}";
            # default to only password logins
            allowedLoginMethods = lib.mkIf (!is-auth-enabled) [ "password" ];
            # default to password if sso is off
            loginMethod = lib.mkIf (!is-auth-enabled) [ "password" ];
          };
        };
        systemd = {
          services = {
            # Make sure all systemd units your module adds belong to a slice.
            # Slice must be named the same as your module id.
            # If your module id contains `-`, replace them with `_`.
            # For example, "my-awesome-service" becomes "my_awesome_service.slice"
            actual = {
              serviceConfig.Slice = "actual.slice";

            };
          };
          # Define the slice itself
          slices.actual = {
            description = "Actual server service slice";
          };
        };
        # You can define a reverse proxy for your service like this
        services.nginx.virtualHosts."${cfg.subdomain}.${sp.domain}" = {
          useACMEHost = sp.domain;
          forceSSL = true;
          # extraConfig = ''
          #   add_header Strict-Transport-Security $hsts_header;
          #   add_header 'Referrer-Policy' 'origin-when-cross-origin';
          #   add_header X-Frame-Options SAMEORIGIN;
          #   add_header X-Content-Type-Options nosniff;
          #   add_header X-XSS-Protection "1; mode=block";
          #   proxy_cookie_path / "/; secure; HttpOnly; SameSite=strict";
          # '';
          locations = {
            "/" = {
              proxyPass = "http://127.0.0.1:5006";
            };
          };
        };
      }
      # SSO config
      (lib.mkIf is-auth-enabled {
        services.actual = {
          settings = {
            # permit openid logins
            allowedLoginMethods = [ "openid" ];
            # default to openid if enabled
            loginMethod = [ "openid" ];
            # SSO config
            openId = {
              discoveryURL = oauthDiscoveryURL;
              client_id = oauthClientID;
              client_secret = oauthClientSecretFP;
              server_hostname = full-domain;
              authMethod = "openid";
            };
            # ACTUAL_OPENID_DISCOVERY_URL = ""; # URL for the OpenID Provider
            # ACTUAL_OPENID_CLIENT_ID = ""; # client_id given by the provider
            # ACTUAL_OPENID_CLIENT_SECRET = ""; # client_secret given by the provider
            # ACTUAL_OPENID_SERVER_HOSTNAME = ""; # Your Actual Server URL (so the provider redirects you to this)
          };
        };
        selfprivacy.auth.clients."${oauthClientID}" = {
          inherit usersGroup;
          imageFile = ./icon.svg;
          displayName = "Actual";
          subdomain = cfg.subdomain;
          originLanding = landing-uri;
          originUrl = redirect-uri;
          clientSystemdUnits = [ "actual.service" ];
          enablePkce = true;
          linuxUserOfClient = linuxUserOfService;
          linuxGroupOfClient = linuxGroupOfService;
          useShortPreferredUsername = true;
        };
      })
    ]
  );

}
