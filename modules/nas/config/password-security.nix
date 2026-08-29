{ config, lib, pkgs, ... }:

let
  pwnedPasswords = pkgs.python3Packages.buildPythonPackage rec {
    pname = "pwnedpasswords";
    version = "3.1.0";
    pyproject = true;
    src = pkgs.fetchPypi {
      inherit pname version;
      hash = "sha256-Vb62EW4+xBns0NaDWyWvmSSj3dco7rwKxglD0Fb8NLg=";
    };
    build-system = [ pkgs.python3Packages.setuptools ];
    doCheck = false;
  };

  passwordPython = pkgs.python3.withPackages (pythonPackages: [
    pythonPackages.zxcvbn
    pwnedPasswords
  ]);
  breachSocket = "/run/nas-password-breach/check.sock";

  breachHelperSource = pkgs.writeText "nas-password-breach-helper.py" ''
    import json
    import os
    import pathlib
    import socketserver

    import pwnedpasswords

    SOCKET_PATH = pathlib.Path(${builtins.toJSON breachSocket})
    MAX_REQUEST_BYTES = 4096
    MAX_PASSWORD_LENGTH = 256


    class Handler(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            password = ""
            try:
                raw = self.rfile.readline(MAX_REQUEST_BYTES + 1)
                if not raw or len(raw) > MAX_REQUEST_BYTES:
                    raise ValueError("request size")
                request = json.loads(raw)
                if not isinstance(request, dict) or set(request) != {"password"}:
                    raise ValueError("request contract")
                password = request.get("password")
                if (
                    not isinstance(password, str)
                    or not password
                    or len(password) > MAX_PASSWORD_LENGTH
                    or any(character in password for character in ("\\0", "\\n", "\\r"))
                ):
                    raise ValueError("password")
                try:
                    count = int(pwnedpasswords.check(password, plain_text=True, timeout=3.0))
                    status = "breached" if count > 0 else "clean"
                except Exception:
                    status = "unavailable"
                    count = None
                response = {"schemaVersion": 1, "status": status, "count": count}
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                response = {"schemaVersion": 1, "status": "invalid", "count": None}
            finally:
                password = ""
            self.wfile.write((json.dumps(response, sort_keys=True) + "\\n").encode("utf-8"))


    class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True


    SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    SOCKET_PATH.unlink(missing_ok=True)
    with Server(str(SOCKET_PATH), Handler) as server:
        os.chmod(SOCKET_PATH, 0o600)
        server.serve_forever()
  '';

  passwordQualitySource = pkgs.writeText "nas-password-quality.py" ''
    import json
    import socket
    import sys

    from zxcvbn import zxcvbn

    MAX_INPUT_BYTES = 16 * 1024
    MAX_PASSWORD_LENGTH = 256
    MINIMUM_LENGTH = 15
    MINIMUM_ZXCVBN_SCORE = 3
    BREACH_SOCKET = ${builtins.toJSON breachSocket}


    def fail(message: str) -> None:
        print(json.dumps({"error": message}, sort_keys=True))
        raise SystemExit(2)


    def breach_check(password: str) -> tuple[str, int | None]:
        payload = (json.dumps({"password": password}, separators=(",", ":")) + "\\n").encode("utf-8")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(4.5)
                client.connect(BREACH_SOCKET)
                client.sendall(payload)
                client.shutdown(socket.SHUT_WR)
                raw = client.recv(4097)
            if len(raw) > 4096:
                return "unavailable", None
            value = json.loads(raw)
            if (
                not isinstance(value, dict)
                or value.get("schemaVersion") != 1
                or value.get("status") not in {"clean", "breached", "unavailable"}
            ):
                return "unavailable", None
            count = value.get("count")
            if count is not None and (not isinstance(count, int) or isinstance(count, bool) or count < 0):
                return "unavailable", None
            return value["status"], count
        except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
            return "unavailable", None
        finally:
            payload = b""


    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        fail("password-quality request exceeds its size limit")
    try:
        request = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("password-quality request is invalid JSON")
    if not isinstance(request, dict) or set(request) != {"password", "userInputs"}:
        fail("password-quality request contract is invalid")

    password = request.get("password")
    user_inputs = request.get("userInputs")
    if (
        not isinstance(password, str)
        or not password
        or len(password) > MAX_PASSWORD_LENGTH
        or any(character in password for character in ("\\0", "\\n", "\\r"))
    ):
        fail("password is invalid")
    if (
        not isinstance(user_inputs, list)
        or len(user_inputs) > 16
        or not all(isinstance(value, str) and len(value) <= 320 for value in user_inputs)
    ):
        fail("password context is invalid")

    context = [value for value in user_inputs if value]
    context.extend([socket.gethostname(), "Nix-nas", "NixOS NAS"])
    strength = zxcvbn(password, user_inputs=context)
    score = int(strength.get("score", 0))
    feedback = strength.get("feedback") if isinstance(strength.get("feedback"), dict) else {}
    warning = feedback.get("warning") if isinstance(feedback.get("warning"), str) else ""
    suggestions = feedback.get("suggestions") if isinstance(feedback.get("suggestions"), list) else []
    suggestions = [value for value in suggestions if isinstance(value, str)][:8]

    # The privileged setup API is AF_UNIX-only. HIBP access is delegated to a
    # separate DynamicUser service with network access but no appliance state.
    breach_status, breach_count = breach_check(password)

    local_accepted = len(password) >= MINIMUM_LENGTH and score >= MINIMUM_ZXCVBN_SCORE
    accepted = local_accepted and breach_status != "breached"
    response = {
        "schemaVersion": 1,
        "accepted": accepted,
        "localAccepted": local_accepted,
        "minimumLength": MINIMUM_LENGTH,
        "minimumZxcvbnScore": MINIMUM_ZXCVBN_SCORE,
        "zxcvbnScore": score,
        "warning": warning,
        "suggestions": suggestions,
        "breachStatus": breach_status,
        "breachCount": breach_count,
    }
    print(json.dumps(response, sort_keys=True))

    password = ""
    request.clear()
    context.clear()
  '';

  passwordQuality = pkgs.writeShellScriptBin "nas-password-quality" ''
    exec ${passwordPython}/bin/python3 ${passwordQualitySource}
  '';
in
{
  systemd.services.nas-password-breach = {
    description = "Unprivileged HIBP password-range lookup helper";
    wantedBy = [ "multi-user.target" ];
    before = [ "nas-first-run-api.service" ];
    unitConfig.ConditionPathExists = "!/var/lib/nas-setup/state.json";
    serviceConfig = {
      Type = "simple";
      DynamicUser = true;
      RuntimeDirectory = "nas-password-breach";
      RuntimeDirectoryMode = "0700";
      ExecStart = "${passwordPython}/bin/python3 ${breachHelperSource}";
      Restart = "on-failure";
      RestartSec = "2s";
      UMask = "0077";
      NoNewPrivileges = true;
      PrivateTmp = true;
      PrivateDevices = true;
      ProtectHome = true;
      ProtectSystem = "strict";
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectKernelLogs = true;
      ProtectControlGroups = true;
      RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
      RestrictRealtime = true;
      RestrictSUIDSGID = true;
      LockPersonality = true;
    };
  };

  # The root setup API remains network-isolated. It can invoke only the local
  # zxcvbn client, which delegates the HIBP range request over a private Unix
  # socket to the DynamicUser helper above.
  systemd.services.nas-first-run-api = {
    requires = [ "nas-password-breach.service" ];
    after = [ "nas-password-breach.service" ];
    path = lib.mkBefore [ passwordQuality ];
  };

  # Future local `passwd` changes use the distro-native libpwquality PAM module.
  # Setup itself additionally applies the zxcvbn/HIBP policy before chpasswd.
  security.pam.services.passwd.rules.password.pwquality = {
    control = "requisite";
    modulePath = "${pkgs.libpwquality.lib}/lib/security/pam_pwquality.so";
    order = config.security.pam.services.passwd.rules.password.unix.order - 10;
    settings = {
      retry = 3;
      minlen = 15;
      dictcheck = 1;
      usercheck = 1;
      enforce_for_root = true;
    };
  };
}
