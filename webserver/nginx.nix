{ config, lib, ... }:
let
  domain = config.selfprivacy.domain;
in
{
  services.nginx = {
    enable = true;
    recommendedGzipSettings = true;
    recommendedOptimisation = true;
    recommendedProxySettings = true;
    recommendedTlsSettings = true;
    sslProtocols = lib.mkForce "TLSv1.2 TLSv1.3";
    sslCiphers = lib.mkForce "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!SHA1:!SHA256:!SHA384:!DSS:!aNULL";
    clientMaxBodySize = "1024m";
    commonHttpConfig = ''
      map $scheme $hsts_header {
          https   "max-age=31536000; includeSubdomains; preload";
      }
      proxy_headers_hash_bucket_size 128;
      proxy_headers_hash_max_size 512;
    '';
    virtualHosts = {
      "${domain}" = {
        useACMEHost = "root-${domain}";
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
            root = "/var/www/root";
          };
        };
      };
      "api.${domain}" = {
        useACMEHost = domain;
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
            proxyPass = "http://127.0.0.1:5050";
            proxyWebsockets = true;
          };
          "/internal" = {
            return = 403;
          };
        };
      };
    };
  };
  systemd.tmpfiles.rules = [
    "d /var/www/root 0750 nginx nginx - -"
  ];
}
