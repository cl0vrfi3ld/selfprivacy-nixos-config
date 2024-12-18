{ config, lib, pkgs, ... }:
let
  sp = config.selfprivacy;
  stateDir =
    if sp.useBinds
    then "/volumes/${cfg.location}/gitea"
    else "/var/lib/gitea";
  cfg = sp.modules.gitea;
  themes = [
    "forgejo-auto"
    "forgejo-light"
    "forgejo-dark"
    "gitea-auto"
    "gitea-light"
    "gitea-dark"
  ];
in
{
  options.selfprivacy.modules.gitea = {
    enable = (lib.mkOption {
      default = false;
      type = lib.types.bool;
      description = "Enable Forgejo";
    }) // {
      meta = {
        type = "enable";
      };
    };
    location = (lib.mkOption {
      type = lib.types.str;
      description = "Forgejo location";
    }) // {
      meta = {
        type = "location";
      };
    };
    subdomain = (lib.mkOption {
      default = "git";
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
    appName = (lib.mkOption {
      default = "SelfPrivacy git Service";
      type = lib.types.str;
      description = "The name displayed in the web interface";
    }) // {
      meta = {
        type = "string";
        weight = 1;
      };
    };
    enableLfs = (lib.mkOption {
      default = true;
      type = lib.types.bool;
      description = "Enable Git LFS";
    }) // {
      meta = {
        type = "bool";
        weight = 2;
      };
    };
    forcePrivate = (lib.mkOption {
      default = false;
      type = lib.types.bool;
      description = "Force all new repositories to be private";
    }) // {
      meta = {
        type = "bool";
        weight = 3;
      };
    };
    disableRegistration = (lib.mkOption {
      default = false;
      type = lib.types.bool;
      description = "Disable registration of new users";
    }) // {
      meta = {
        type = "bool";
        weight = 4;
      };
    };
    requireSigninView = (lib.mkOption {
      default = false;
      type = lib.types.bool;
      description = "Force users to log in to view any page";
    }) // {
      meta = {
        type = "bool";
        weight = 5;
      };
    };
    defaultTheme = (lib.mkOption {
      default = "forgejo-auto";
      type = lib.types.enum themes;
      description = "Default theme";
    }) // {
      meta = {
        type = "enum";
        options = themes;
        weight = 6;
      };
    };
  };

  config = lib.mkIf cfg.enable {
    fileSystems = lib.mkIf sp.useBinds {
      "/var/lib/gitea" = {
        device = "/volumes/${cfg.location}/gitea";
        options = [ "bind" ];
      };
    };
    services.gitea.enable = false;
    services.forgejo = {
      enable = true;
      package = pkgs.forgejo;
      inherit stateDir;
      user = "gitea";
      group = "gitea";
      database = {
        type = "sqlite3";
        host = "127.0.0.1";
        name = "gitea";
        user = "gitea";
        path = "${stateDir}/data/gitea.db";
        createDatabase = true;
      };
      # ssh = {
      #   enable = true;
      #   clonePort = 22;
      # };
      lfs = {
        enable = cfg.enableLfs;
        contentDir = "${stateDir}/lfs";
      };
      repositoryRoot = "${stateDir}/repositories";
      #      cookieSecure = true;
      settings = {
        DEFAULT = {
          APP_NAME = "${cfg.appName}";
        };
        server = {
          DOMAIN = "${cfg.subdomain}.${sp.domain}";
          ROOT_URL = "https://${cfg.subdomain}.${sp.domain}/";
          HTTP_ADDR = "0.0.0.0";
          HTTP_PORT = 3000;
        };
        mailer = {
          ENABLED = false;
        };
        ui = {
          DEFAULT_THEME = cfg.defaultTheme;
          SHOW_USER_EMAIL = false;
        };
        picture = {
          DISABLE_GRAVATAR = true;
        };
        admin = {
          ENABLE_KANBAN_BOARD = true;
        };
        repository = {
          FORCE_PRIVATE = cfg.forcePrivate;
        };
        session = {
          COOKIE_SECURE = true;
        };
        log = {
          ROOT_PATH = "${stateDir}/log";
          LEVEL = "Warn";
        };
        service = {
          DISABLE_REGISTRATION = cfg.disableRegistration;
          REQUIRE_SIGNIN_VIEW = cfg.requireSigninView;
        };
      };
    };
    users.users.gitea = {
      home = "${stateDir}";
      useDefaultShell = true;
      group = "gitea";
      isSystemUser = true;
    };
    users.groups.gitea = { };
    services.nginx.virtualHosts."${cfg.subdomain}.${sp.domain}" = {
      useACMEHost = sp.domain;
      forceSSL = true;
      extraConfig = ''
        add_header Strict-Transport-Security $hsts_header;
        #add_header Content-Security-Policy "script-src 'self'; object-src 'none'; base-uri 'none';" always;
        add_header 'Referrer-Policy' 'origin-when-cross-origin';
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";
        proxy_cookie_path / "/; secure; HttpOnly; SameSite=strict";
      '';
      locations = {
        "/" = {
          proxyPass = "http://127.0.0.1:3000";
        };
      };
    };
    systemd = {
      services.forgejo = {
        unitConfig.RequiresMountsFor = lib.mkIf sp.useBinds "/volumes/${cfg.location}/gitea";
        serviceConfig = {
          Slice = "gitea.slice";
        };
      };
      slices.gitea = {
        description = "Forgejo service slice";
      };
    };

  };
}
