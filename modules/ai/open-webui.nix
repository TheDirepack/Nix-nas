{ config, lib, pkgs, aiInternal, ... }:

let
  inherit (aiInternal)
    aiSecretDir
    cfg
    lanHost
  ;
in
{
  config = lib.mkIf cfg.enable {
    services.open-webui = {
      enable = true;
      host = "127.0.0.1";
      port = cfg.openWebuiPort;
      environmentFile = "${aiSecretDir}/open-webui.env";
      environment = {
        WEBUI_URL = "https://${lanHost}/ai";
        WEBUI_AUTH = "True";
        ENABLE_LOGIN_FORM = "False";
        ENABLE_PASSWORD_AUTH = "False";
        ENABLE_PASSWORD_CHANGE_FORM = "False";
        WEBUI_SESSION_COOKIE_SECURE = "True";
        WEBUI_AUTH_COOKIE_SECURE = "True";
        WEBUI_SESSION_COOKIE_SAME_SITE = "lax";
        WEBUI_AUTH_COOKIE_SAME_SITE = "lax";
        ENABLE_SIGNUP = "True";
        DEFAULT_USER_ROLE = "user";
        WEBUI_AUTH_TRUSTED_EMAIL_HEADER = "Remote-Email";
        WEBUI_AUTH_TRUSTED_NAME_HEADER = "Remote-Name";
        WEBUI_AUTH_TRUSTED_GROUPS_HEADER = "Remote-Groups";
        WEBUI_AUTH_TRUSTED_ROLE_HEADER = "Remote-Role";
        OPENAI_API_BASE_URL = "http://127.0.0.1:${toString cfg.llamaSwap.port}/v1";
        ENABLE_OLLAMA_API = "False";
        ENABLE_DIRECT_CONNECTIONS = "False";
        ENABLE_VERSION_UPDATE_CHECK = "False";
        ENABLE_ADMIN_CHAT_ACCESS = "False";
        CORS_ALLOW_ORIGIN = "https://${lanHost}";
        SCARF_NO_ANALYTICS = "True";
        DO_NOT_TRACK = "True";
        ANONYMIZED_TELEMETRY = "False";
      };
    };
  };
}
