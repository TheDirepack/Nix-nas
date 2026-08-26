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

  passwordQualitySource = pkgs.writeText "nas-password-quality.py" ''
    import json
    import socket
    import sys

    import pwnedpasswords
    from zxcvbn import zxcvbn

    MAX_INPUT_BYTES = 16 * 1024
    MAX_PASSWORD_LENGTH = 256
    MINIMUM_LENGTH = 15
    MINIMUM_ZXCVBN_SCORE = 3


    def fail(message: str) -> None:
        print(json.dumps({"error": message}, sort_keys=True))
        raise SystemExit(2)


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
        or any(character in password for character in ("\0", "\n", "\r"))
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

    breach_status = "unavailable"
    breach_count = None
    try:
        # pwnedpasswords uses the HIBP range API: only the first five SHA-1
        # characters leave the host. A short timeout keeps offline setup usable.
        breach_count = int(pwnedpasswords.check(password, plain_text=True, timeout=3.0))
        breach_status = "breached" if breach_count > 0 else "clean"
    except Exception:
        # HIBP is supplemental. Local strength policy remains authoritative
        # when the network/service is unavailable during first boot.
        breach_status = "unavailable"
        breach_count = None

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

    # Drop the strongest live references before normal interpreter teardown.
    password = ""
    request.clear()
    context.clear()
  '';

  passwordQuality = pkgs.writeShellScriptBin "nas-password-quality" ''
    exec ${passwordPython}/bin/python3 ${passwordQualitySource}
  '';
in
{
  # The standalone setup API performs zxcvbn + HIBP validation. Keep the
  # helper out of the global PATH so ordinary processes do not gain another
  # network-capable utility unnecessarily.
  systemd.services.nas-first-run-api.path = lib.mkBefore [ passwordQuality ];

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
