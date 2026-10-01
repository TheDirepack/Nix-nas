# shellcheck shell=bash

require_secret_atom() {
  local value="$1" label="$2" minimum="${3:-8}" maximum="${4:-4096}"
  if (( ${#value} < minimum || ${#value} > maximum )) || [[ ! "$value" =~ ^[A-Za-z0-9._~+/=:@-]+$ ]]; then
    echo "$label has an unsafe or unexpected format in KeePassXC." >&2
    return 1
  fi
}

require_secret_hex() {
  local value="$1" expected="$2" label="$3"
  if (( ${#value} != expected )) || [[ ! "$value" =~ ^[0-9A-Fa-f]+$ ]]; then
    echo "$label has an unsafe or unexpected format in KeePassXC." >&2
    return 1
  fi
}

require_ntfy_topic() {
  local value="$1"
  if (( ${#value} < 8 || ${#value} > 128 )) || [[ ! "$value" =~ ^[A-Za-z0-9_-]+$ ]]; then
    echo "ntfy alert topic has an unsafe or unexpected format in KeePassXC." >&2
    return 1
  fi
}

require_huggingface_token() {
  local value="$1"
  [[ -z "$value" || "$value" =~ ^hf_[A-Za-z0-9]{20,}$ ]] || {
    echo "Hugging Face token has an unsafe or unexpected format in KeePassXC." >&2
    return 1
  }
}

install_secret() {
  local source="$1" target="$2" owner="$3" group="$4"
  [[ -f "$source" && ! -L "$source" ]] || {
    echo "Refusing to install a non-regular or symlink secret source: $source" >&2
    return 1
  }
  sudo install -m 0400 -o "$owner" -g "$group" -- "$source" "$target"
}
