{
  description = "yet another mcp obsidian server, for obsidian livesync via couchdb";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs @ {
    flake-parts,
    crane,
    ...
  }:
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];

      flake = {
        nixosModules.default = {
          config,
          lib,
          pkgs,
          ...
        }: let
          cfg = config.services.yamos;
          couchdbCfg = config.services.couchdb;
          inherit
            (lib)
            mkEnableOption
            mkOption
            mkPackageOption
            mkIf
            mkDefault
            types
            literalExpression
            ;

          # Convert settings attrset to environment variables
          settingsToEnv = settings:
            lib.mapAttrs' (name: value:
              lib.nameValuePair name (
                if builtins.isBool value
                then
                  (
                    if value
                    then "true"
                    else "false"
                  )
                else toString value
              )) (lib.filterAttrs (_: v: v != null) settings);
        in {
          options.services.yamos = {
            enable = mkEnableOption "yamos MCP server for Obsidian LiveSync";

            package = mkPackageOption inputs.self.packages.${pkgs.system} "yamos" {
              default = "yamos";
            };

            settings = mkOption {
              type = types.submodule {
                freeformType = types.attrsOf (types.nullOr (types.oneOf [
                  types.str
                  types.int
                  types.bool
                ]));

                options = {
                  MCP_TRANSPORT = mkOption {
                    type = types.enum ["stdio" "sse"];
                    default = "sse";
                    description = "Transport mode for the MCP server.";
                  };

                  MCP_HOST = mkOption {
                    type = types.str;
                    default = "127.0.0.1";
                    description = "Host to bind the SSE server to.";
                  };

                  MCP_PORT = mkOption {
                    type = types.port;
                    default = 3000;
                    description = "Port to bind the SSE server to.";
                  };

                  BASE_PATH = mkOption {
                    type = types.str;
                    default = "";
                    description = "Base path for the server (useful for reverse proxies).";
                  };

                  PUBLIC_URL = mkOption {
                    type = types.nullOr types.str;
                    default = null;
                    description = "Public URL for OAuth callbacks.";
                  };

                  COUCHDB_URL = mkOption {
                    type = types.str;
                    description = "CouchDB server URL. Defaults to http:// with services.couchdb settings when CouchDB is enabled.";
                    defaultText = literalExpression ''"http://\${config.services.couchdb.bindAddress}:\${toString config.services.couchdb.port}"'';
                  };

                  COUCHDB_DATABASE = mkOption {
                    type = types.str;
                    default = "obsidian";
                    description = "CouchDB database name.";
                  };

                  COUCHDB_USER = mkOption {
                    type = types.nullOr types.str;
                    default = "admin";
                    description = "CouchDB username. Set password via environmentFile for security.";
                  };

                  RATE_LIMIT_PER_SECOND = mkOption {
                    type = types.int;
                    default = 10;
                    description = "Rate limit requests per second.";
                  };

                  RATE_LIMIT_BURST = mkOption {
                    type = types.int;
                    default = 100;
                    description = "Rate limit burst size.";
                  };

                  OAUTH_ENABLED = mkOption {
                    type = types.bool;
                    default = false;
                    description = "Enable OAuth authentication.";
                  };

                  OAUTH_CLIENT_ID = mkOption {
                    type = types.nullOr types.str;
                    default = null;
                    description = "OAuth client ID.";
                  };

                  OAUTH_TOKEN_EXPIRATION = mkOption {
                    type = types.int;
                    default = 3600;
                    description = "OAuth access token expiration in seconds (0 = no expiration).";
                  };

                  OAUTH_REFRESH_TOKEN_EXPIRATION = mkOption {
                    type = types.int;
                    default = 2592000;
                    description = "OAuth refresh token expiration in seconds (default 30 days).";
                  };

                  OAUTH_STRICT_ROTATION = mkOption {
                    type = types.bool;
                    default = false;
                    description = "If true, invalidate token family on refresh token reuse. If false, just log a warning.";
                  };

                  RUST_LOG = mkOption {
                    type = types.str;
                    default = "info";
                    description = "Log level configuration.";
                  };
                };
              };
              default = {};
              description = ''
                Configuration settings for yamos. These are converted to environment variables.

                Use `environmentFile` for secrets like COUCHDB_PASSWORD, OAUTH_JWT_SECRET,
                OAUTH_CLIENT_SECRET, and MCP_AUTH_TOKEN.

                Any additional settings can be added here and will be passed as environment
                variables, allowing forward-compatibility with new yamos options.
              '';
              example = literalExpression ''
                {
                  MCP_PORT = 8080;
                  COUCHDB_URL = "http://192.168.1.10:5984";
                  COUCHDB_DATABASE = "my-vault";
                  OAUTH_ENABLED = true;
                  OAUTH_CLIENT_ID = "my-client";
                  # New options can be added without module updates:
                  SOME_FUTURE_OPTION = "value";
                }
              '';
            };

            environmentFile = mkOption {
              type = types.nullOr (types.either types.path types.str);
              default = null;
              description = ''
                Path to an environment file containing secrets.
                Accepts either a path (copied to nix store) or a string path
                for compatibility with sops-nix and other secret management
                tools that provide runtime paths.

                This file should contain sensitive values like:
                - COUCHDB_PASSWORD
                - OAUTH_JWT_SECRET
                - OAUTH_CLIENT_SECRET
                - MCP_AUTH_TOKEN

                The file format is one VAR=value per line.
              '';
              example = "/run/secrets/yamos.env";
            };

            extraEnvironmentFiles = mkOption {
              type = types.listOf (types.either types.path types.str);
              default = [];
              description = ''
                Additional environment files to load.
                Useful for splitting secrets or adding new options.
                Accepts either paths or string paths for sops-nix compatibility.
              '';
            };

            user = mkOption {
              type = types.str;
              default = "yamos";
              description = "User account under which yamos runs.";
            };

            group = mkOption {
              type = types.str;
              default = "yamos";
              description = "Group under which yamos runs.";
            };
          };

          config = mkIf cfg.enable {
            # Default COUCHDB_URL based on services.couchdb if enabled
            services.yamos.settings.COUCHDB_URL = mkDefault (
              if couchdbCfg.enable
              then "http://${couchdbCfg.bindAddress}:${toString couchdbCfg.port}"
              else "http://localhost:5984"
            );

            users.users.${cfg.user} = {
              isSystemUser = true;
              group = cfg.group;
              description = "yamos service user";
            };

            users.groups.${cfg.group} = {};

            systemd.services.yamos = {
              description = "yamos MCP server for Obsidian LiveSync";
              wantedBy = ["multi-user.target"];
              after = ["network.target"] ++ lib.optional couchdbCfg.enable "couchdb.service";
              wants = lib.optional couchdbCfg.enable "couchdb.service";

              environment = settingsToEnv cfg.settings;

              serviceConfig = {
                Type = "simple";
                User = cfg.user;
                Group = cfg.group;
                ExecStart = "${cfg.package}/bin/yamos";
                Restart = "on-failure";
                RestartSec = 5;

                EnvironmentFile =
                  lib.optional (cfg.environmentFile != null) cfg.environmentFile
                  ++ cfg.extraEnvironmentFiles;

                # Security hardening
                NoNewPrivileges = true;
                ProtectSystem = "strict";
                ProtectHome = true;
                PrivateTmp = true;
                PrivateDevices = true;
                ProtectKernelTunables = true;
                ProtectKernelModules = true;
                ProtectControlGroups = true;
                RestrictAddressFamilies = ["AF_INET" "AF_INET6"];
                RestrictNamespaces = true;
                LockPersonality = true;
                MemoryDenyWriteExecute = true;
                RestrictRealtime = true;
                RestrictSUIDSGID = true;
              };
            };
          };
        };
      };

      perSystem = {
        config,
        self',
        inputs',
        pkgs,
        system,
        ...
      }: let
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = ["rust-src" "rust-analyzer"];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # Common source filtering
        src = craneLib.cleanCargoSource ./.;

        # Common arguments for all builds
        commonArgs = {
          inherit src;
          strictDeps = true;

          nativeBuildInputs = with pkgs; [
            pkg-config
          ];

          buildInputs = with pkgs;
            [
              openssl
            ]
            ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
              pkgs.darwin.apple_sdk.frameworks.Security
              pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
            ];
        };

        # Build just the cargo dependencies for caching
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        # Build the actual package
        yamos = craneLib.buildPackage (commonArgs
          // {
            inherit cargoArtifacts;
          });
      in {
        _module.args.pkgs = import inputs.nixpkgs {
          inherit system;
          overlays = [(import inputs.rust-overlay)];
        };

        checks = {
          inherit yamos;

          # Run clippy
          clippy = craneLib.cargoClippy (commonArgs
            // {
              inherit cargoArtifacts;
              cargoClippyExtraArgs = "--all-targets -- --deny warnings";
            });

          # Check formatting
          fmt = craneLib.cargoFmt {
            inherit src;
          };
        };

        packages = {
          default = yamos;
          inherit yamos;
        };

        devShells.default = craneLib.devShell {
          checks = self'.checks;

          packages = with pkgs; [
            cargo-update
            cargo-edit
            curl
            jq
          ];

          RUST_LOG = "yamos=debug";

          shellHook = ''
            echo "yamos dev shell"
            echo ""
            echo "Quick start:"
            echo "  1. cp .env.example .env"
            echo "  2. Edit .env with your CouchDB credentials"
            echo "  3. cargo run -- --transport sse"
            echo ""
            echo "For production build:"
            echo "  nix build"
          '';
        };
      };
    };
}
