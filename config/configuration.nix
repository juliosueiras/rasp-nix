# Edit this configuration file to define what should be installed on
# your system.  Help is available in the configuration.nix(5) man page
# and in the NixOS manual (accessible by running ‘nixos-help’).

{ lib, config, pkgs, ... }:

let
  customPythonPackages = import /home/julio/test_py/test/default.nix { };
  chiaki = import /home/julio/chiaki/default.nix;
  hass = pkgs.home-assistant.override {
    extraComponents = [ "default_config" "mobile_app" "hue" ];
    extraPackages = ps: with ps; [pillow aiohue] ++ customPythonPackages.packageList;

    packageOverrides = self: super: {
      aiohttp = customPythonPackages.packages.aiohttp;
    };

  };

  finalHass = hass.overridePythonAttrs (oldAttrs: {
    checkPhase = "true";
    patches = oldAttrs.patches ++ [ /home/julio/remove_auto_correct.patch ];
  });

  hassConfigJSON = pkgs.writeText "configuration.json"
    (builtins.toJSON config.services.home-assistant.config);

  ocserv-certs =
    pkgs.runCommand "ocserv-certs" { preferLocalBuild = true; } ''
      ${pkgs.openssl}/bin/openssl genrsa -des3 -passout pass:xxxx -out ca.pass.key 2048
      ${pkgs.openssl}/bin/openssl rsa -passin pass:xxxx -in ca.pass.key -out ca.key
      ${pkgs.openssl}/bin/openssl req -new -key ca.key -out ca.csr \
      -subj "/C=UK/ST=Warwickshire/L=Leamington/O=OrgName/OU=Security Department/CN=example.com"
      ${pkgs.openssl}/bin/openssl x509 -req -days 1 -in ca.csr -signkey ca.key -out ca.crt
      
      # Create key
       ${pkgs.openssl}/bin/openssl genrsa -des3 -passout pass:xxxx -out server.pass.key 2048
       ${pkgs.openssl}/bin/openssl rsa -passin pass:xxxx -in server.pass.key -out server.key
       ${pkgs.openssl}/bin/openssl req -new -key server.key -out server.csr \
       -subj "/C=UK/ST=Warwickshire/L=Leamington/O=OrgName/OU=IT Department/CN=example.com"
       ${pkgs.openssl}/bin/openssl x509 -req -days 1 -in server.csr -CA ca.crt \
       -CAkey ca.key -CAserial ca.srl -CAcreateserial \
       -out server.crt
      
       # Copy key to destination
       # Create fullchain.pem (same format as "simp_le ... -f fullchain.pem" creates)
       cat {server.crt,ca.crt} > fullchain.pem
       mkdir $out
       cp * $out
    '';

  hassConfigFile =
    pkgs.runCommand "configuration.yaml" { preferLocalBuild = true; } ''
      ${pkgs.remarshal}/bin/json2yaml -i ${hassConfigJSON} -o $out
# Hack to support secrets, that are encoded as custom yaml objects,
# https://www.home-assistant.io/docs/configuration/secrets/
sed -i -e "s/'\!secret \(.*\)'/\!secret \1/" $out
sed -i -e "s/'\!include_dir_merge_named \(.*\)'/\!include_dir_merge_named \1/" $out
    '';

  consul = pkgs.stdenv.mkDerivation {
    name = "consul";

    buildInputs = [
      pkgs.autoPatchelfHook
    ];

    src = pkgs.fetchzip {
      url = "https://releases.hashicorp.com/consul/1.8.0-beta1/consul_1.8.0-beta1_linux_arm64.zip";
      sha256 = "1zp0kv68pcrpxrp10y8lg6sdvgq0lwq0hkzblnjapnkcl6673dfy";
    };

    outputs = [ "bin" "out" ];

    installPhase = ''
    mkdir -p $out/bin
    mkdir -p $bin/bin

    cp consul $out/bin/
    cp consul $bin/bin/
    '';
  };
in {
  imports = [ # Include the results of the hardware scan.
    ./hardware-configuration.nix
  ];

  # Use the GRUB 2 boot loader.
  boot.loader.grub.enable = false;
  boot.kernelPackages = pkgs.linuxPackages_rpi4;

  boot.loader.raspberryPi = {
    enable = true;
    version = 4;
    firmwareConfig = ''
      gpu_mem=192
    '';
  };

  security.sudo.wheelNeedsPassword = false;

  nixpkgs = {
    config = {
      allowUnfree = true;
      allowUnsupportedSystem = true;
    };
  };

  users.extraUsers = {
    julio = {
      isNormalUser = true;
      initialPassword = "<password>";
      extraGroups = [ "wheel" ];

      uid = 1000;
    };

    robert = {
      isNormalUser = true;
      initialPassword = "<password>";
    };

    martin = {
      isNormalUser = true;
      initialPassword = "<password>";
    };
  };


  system.stateVersion = "20.03"; # Did you read the comment?

  services.openssh.enable = true;

  services.ttyd = {
    enable = true;
  };

  services.xrdp = {
    enable = true;

    defaultWindowManager = "${pkgs.awesome}/bin/awesome";
  };

  services.xserver = {
    enable = true;

    displayManager = {
      defaultSession = "none+awesome";
      lightdm = {
        greeter.enable = false;
        autoLogin = {
          enable = true;
          user = "julio";
          timeout = 0;
        };
        enable = true;
      };
    };

    desktopManager = { xterm.enable = false; };

    windowManager = { awesome = { enable = true; }; };

    videoDrivers = [ "modesetting" ];
  };

  environment.systemPackages = [ chiaki pkgs.vim pkgs.htop pkgs.surf pkgs.vlc pkgs.ffmpeg-full pkgs.raspberrypi-tools ];

  networking.wireless = {
    enable = true;
    networks = {
      "TP-Link_E4E8_5G" = { psk = "<password>"; };
    };
  };

  services.blueman.enable = true;
  systemd.enableEmergencyMode = false;
  documentation.enable = false;
  documentation.nixos.enable = false;
  services.nixosManual.showManual = lib.mkForce false;
  boot.cleanTmpDir = true;
  nix.gc.automatic = true;
  nix.gc.options = "--delete-older-than 30d";

  hardware.bluetooth.enable = true;

  hardware.opengl = {
    enable = true;
    setLdLibraryPath = true;
    package = pkgs.mesa_drivers;
  };

  hardware.deviceTree = {
    base = pkgs.device-tree_rpi;
    overlays = [ "${pkgs.device-tree_rpi.overlays}/vc4-fkms-v3d.dtbo" ];
  };

  security.wrappers = {
    hass = {
      source = "${finalHass}/bin/hass";
      capabilities = "cap_net_bind_service+ep";
    };
  };

  networking.nat = {
    enable = true;
    externalInterface = "wlan0";
    internalInterfaces = [ "vpns0" ];
  };

  networking.firewall = {
    allowedTCPPorts = [
      443 80 53 8000 997 config.services.xrdp.port 4433 2049 111 20048
    ];

    allowedUDPPorts = [ 987 53 4433 2049 111 20048];

    allowedUDPPortRanges = [{
      from = 30000;
      to = 65000;
    }];
    
  };


  systemd.services.home-assistant.preStart = ''
    rm -f "${config.services.home-assistant.configDir}/configuration.yaml"
    ln -s ${hassConfigFile} "${config.services.home-assistant.configDir}/configuration.yaml"
  '';

  services.home-assistant = {
    enable = true;
    openFirewall = true;
    package = finalHass;
    config = {
      frontend = { themes = "!include_dir_merge_named themes"; };
      mobile_app = { };
      lovelace = { 
        mode = "yaml";
        resources = [
        {
          url = "/hacsfiles/lovelace-card-mod/card-mod.js";
          type = "module";
        }
        {
          url = "/hacsfiles/lovelace-layout-card/layout-card.js";
          type = "module";
        }];
      };

      ps4 = { };
      config = { };
      panel_iframe = {
        sheridan = {
          title = "Sheridan";
          url = "https://www.sheridancollege.ca";
        };
      };
      homeassistant = {
        name = "Home";
        time_zone = "America/Toronto";
      };
    };
  };

  services.ocserv = {
    enable = true;
    config = ''
     auth = "pam"
     tcp-port = 4433
     udp-port = 4433
     run-as-user = nobody
     run-as-group = nogroup
     listen-proxy-proto = true;
     socket-file = /var/run/ocserv-conn.socket
     server-cert = ${ocserv-certs}/server.crt
     server-key = ${ocserv-certs}/server.key
     keepalive = 32400
     dpd = 90
     mobile-dpd = 1800
     switch-to-tcp-timeout = 25
     try-mtu-discovery = false
     cert-user-oid = 0.9.2342.19200300.100.1.1
     tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0"
     auth-timeout = 240
     min-reauth-time = 300
     max-ban-score = 80
     ban-reset-time = 1200
     cookie-timeout = 300
     deny-roaming = false
     rekey-time = 172800
     rekey-method = ssl
     use-occtl = true
     pid-file = /run/ocserv.pid
     device = vpns
     predictable-ips = true
     default-domain = gateway.fast.sheridanc.on.ca
     #ipv4-network = 192.168.0.32/27
     ipv4-network = 192.168.4.0/24
     #ipv4-netmask = 255.255.255.224
     ipv4-netmask = 255.255.255.0
     dns = 192.168.2.101
     ping-leases = false
     route = 10.10.10.0/255.255.255.0
     route = 192.168.0.0/255.255.0.0
     no-route = 192.168.5.0/255.255.255.0
     cisco-client-compat = true
     dtls-legacy = true
    '';
  };

  boot.kernel.sysctl."net.ipv4.ip_forward" = 1;
  boot.kernel.sysctl."net.ipv4.conf.all.proxy_arp" = 1;


  networking.hosts = {
    "192.168.2.101" = [
      "home-assistant.julio.com"
      "docker.julio.com"
      "consul.julio.com"
      "gitlab.julio.com"
      "main.julio.com"
      "dns.julio.com"
      "rasp-term.julio.com"
    ];

    "192.168.2.100" = ["ps4.julio.com"];
  };

  systemd.services.zipkin = {
    description = "ZipKin Server";
    after = [ "network.target" ];
    serviceConfig = {
      ExecStart = "${pkgs.zipkin}/bin/zipkin-server";
      User = "root";
      Group = "root";
      Restart = "on-failure";
      KillSignal = "SIGINT";
    };
    wantedBy = [ "default.target" ];
  };

  services.gitlab = {
    enable = true;
    host = "gitlab.julio.com";
    initialRootPasswordFile = "/etc/nixos/gitlab-pass";
    secrets = {
      dbFile = "/etc/nixos/gitlab-secrets-pass";
      jwsFile = "/etc/nixos/gitlab-secrets-pass";
      otpFile = "/etc/nixos/gitlab-secrets-pass";
      secretFile = "/etc/nixos/gitlab-secrets-pass";
    };
  };

  services.nginx = {
    enable = true;
    statusPage = true;
    gitweb.enable = true;

    recommendedGzipSettings = true;
    recommendedOptimisation = true;
    recommendedProxySettings = true;
    recommendedTlsSettings = true;

    clientMaxBodySize = "2000M";

    virtualHosts = {
      "home-assistant.julio.com" = {
        locations."/" = {
          proxyPass = "http://localhost:8123";
	  proxyWebsockets = true;
        };
      };

      "rasp-term.julio.com" = {
        locations."/" = {
          proxyPass = "http://localhost:7681";
	  proxyWebsockets = true;
        };
      };

      "docker.julio.com" = {
        listen = [
          {
            addr = "0.0.0.0";
            ssl = true;
            port = 4444;
          }
	];

        onlySSL = true;
	sslCertificate = "${ocserv-certs}/server.crt";
	sslCertificateKey = "${ocserv-certs}/server.key";
        locations."/" = {
          proxyPass = "http://localhost:5000";
          extraConfig = ''
            if ($http_user_agent ~ "^(docker\/1\.(3|4|5(?!\.[0-9]-dev))|Go ).*$" ) {
              return 404;
            }

	    add_header 'Docker-Distribution-Api-Version' 'registry/2.0' always;

            proxy_set_header  X-Real-IP         $remote_addr;
            proxy_set_header  X-Forwarded-For   $proxy_add_x_forwarded_for;
            proxy_set_header  X-Forwarded-Proto $scheme;
	    proxy_read_timeout                  900;
	 '';
        };
      };

      "consul.julio.com" = {
        locations."/" = {
          proxyPass = "http://localhost:8500";
        };
      };

      "gocd.juliosueiras.ca" = {
        addSSL = true;
        enableACME = true;
      
        listen = [
          {
            addr = "0.0.0.0";
            ssl = true;
            port = 4444;
          }

          {
            addr = "0.0.0.0";
            ssl = false;
            port = 80;
          }
        ];

        locations."/" = {
          proxyPass = "https://localhost:8154";
	  proxyWebsockets = true;
        };
      };

      "test.juliosueiras.ca" = {
        addSSL = true;
        enableACME = true;
      
        listen = [
          {
            addr = "0.0.0.0";
            ssl = true;
            port = 4444;
          }

          {
            addr = "0.0.0.0";
            ssl = false;
            port = 80;
          }
        ];

        #acmeFallbackHost = "https://acme-staging-v02.api.letsencrypt.org/directory";

        locations."/" = {
          proxyPass = "http://localhost:80";
	  proxyWebsockets = true;
        };
      };

      "dns.julio.com" = {
        locations."/" = {
          proxyPass = "http://localhost:9411";
	  proxyWebsockets = true;
        };
      };

      "gitlab.julio.com" = {
        locations."/".proxyPass = "http://unix:/run/gitlab/gitlab-workhorse.socket";
      };
    };
  };

  security.acme.email = "juliosueiras@gmail.com";
  security.acme.acceptTerms = true;

  services.coredns = {
    config = ''
  julio.com {
    whoami
    trace zipkin localhost:9411
    hosts
    log
  }

  . {
    whoami
    trace zipkin localhost:9411
    forward . 8.8.8.8 9.9.9.9
    log
  }
    '';

    enable = true;
  };

  systemd.services.home-assistant.serviceConfig.ExecStart =
    lib.mkForce "/run/wrappers/bin/hass --config '/var/lib/hass'";

  services.autossh.sessions = [
    { 
      extraArguments = "-N -R 0.0.0.0:443:localhost:443 -i /etc/nixos/sshKeys/gatewayKey root@gateway.fast.sheridanc.on.ca";
      name = "vpn-forward"; 
      monitoringPort = 20000;
      user = "root";
    }

    { 
      extraArguments = "-N -R 0.0.0.0:80:localhost:8888 -i /etc/nixos/sshKeys/gatewayKey root@gateway.fast.sheridanc.on.ca";
      name = "http-forward"; 
      monitoringPort = 20021;
      user = "root";
    }
  ];

  systemd.services.copy-lovelace = {
    description = "copy-lovelace";
    after = [ "network.target" ];
    serviceConfig = {
      Type = "oneshot";
      ExecStart = "cp ${./lovelace.yaml} ${config.services.home-assistant.configDir}/ui-lovelace.yaml";
      User = "hass";
      Group = "hass";
      Restart = "no";
      KillSignal = "SIGINT";
    };
    wantedBy = [ "default.target" ];
  };


  nix.useSandbox = false;

  virtualisation.docker.enable = true;
 
  services.sniproxy = {
    enable = true;
    config = ''
      listener 0.0.0.0:443 {
         protocol tls
         table HTTPS
      
         #we set fallback to be ocserv as older versions of openconnect 
         #don't advertise the hostname they connect to.
         fallback 127.0.0.1:4433
      }

      listener 0.0.0.0:8888 {
         proto http
         table HTTP
      }
      
      table HTTPS {
         # Match exact request hostnames
         docker.julio.com 127.0.0.1:4444
         test.juliosueiras.ca 127.0.0.1:4444
         gocd.juliosueiras.ca 127.0.0.1:4444
      }

      table HTTP {
         # Match exact request hostnames
         test.juliosueiras.ca 127.0.0.1:80
         gocd.juliosueiras.ca 127.0.0.1:80
      }
    '';
  };

  services.gocd-server.enable = true;
  services.gocd-agent.enable = true;

  services.nfs.server = {
    enable = true;
    exports = ''
/export *(rw,fsid=0,no_subtree_check)
/export/nfs *(rw,nohide,insecure,no_subtree_check,no_root_squash)
    '';
  };

  fileSystems."/export/nfs" = {
    device = "/mnt/nfs";
    options = [ "bind" ];
  };

  services.dockerRegistry.enable = true;

  services.consul = {
    enable = true;
    package = consul;

    webUi = true;

    extraConfig = {
      bootstrap_expect = 1;
      server = true;
      client_addr = "127.0.0.1";

      connect = {
        enabled = true;
      };
    };

    interface = {
      bind = "wlan0";
      advertise = "wlan0";
    };
  };
}
