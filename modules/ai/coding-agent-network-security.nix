{ config, lib, pkgs, ... }:

let
  ai = config.nas.ai;
  code = ai.codingAgent;
  piPackageAvailable = builtins.hasAttr "pi-coding-agent" pkgs;
  piHostVethIp = "10.200.1.1";
  piNsVethIp = "10.200.1.2";
  inputChain = "NAS_PI_INPUT";
  forwardChain = "NAS_PI_FORWARD";
  iptables = "${pkgs.iptables}/bin/iptables";
  ip = "${pkgs.iproute2}/bin/ip";

  secureNetnsStart = pkgs.writeShellScript "nas-pi-netns-secure-setup" ''
    set -euo pipefail

    ${ip} netns add pi 2>/dev/null || true
    ${ip} link add pi-veth0 type veth peer name pi-veth1 2>/dev/null || true
    ${ip} link set pi-veth1 netns pi 2>/dev/null || true
    ${ip} addr add ${piHostVethIp}/30 dev pi-veth0 2>/dev/null || true
    ${ip} link set pi-veth0 up
    ${ip} netns exec pi ${ip} addr add ${piNsVethIp}/30 dev pi-veth1 2>/dev/null || true
    ${ip} netns exec pi ${ip} link set pi-veth1 up
    ${ip} netns exec pi ${ip} link set lo up
    ${ip} netns exec pi ${ip} route replace default via ${piHostVethIp}

    # Build dedicated chains before attaching them. A coding agent is allowed to
    # reach the host only for DNS and the llama-swap proxy. In particular, a
    # process controlled by model output must not probe SSH/Caddy/Cockpit or any
    # other host listener through the veth gateway.
    ${iptables} -N ${inputChain} 2>/dev/null || ${iptables} -F ${inputChain}
    ${iptables} -A ${inputChain} -d ${piHostVethIp}/32 -p udp --dport 53 -j ACCEPT
    ${iptables} -A ${inputChain} -d ${piHostVethIp}/32 -p tcp --dport 53 -j ACCEPT
    ${iptables} -A ${inputChain} -d ${piHostVethIp}/32 -p tcp --dport ${toString ai.llamaSwap.port} -j ACCEPT
    ${iptables} -A ${inputChain} -j REJECT

    # Forward only to public IPv4 destinations. This prevents an LLM-driven
    # session from becoming an SSRF/pivot point into the NAS LAN, VPN ranges,
    # link-local services, carrier-grade NAT space, or other non-public ranges.
    ${iptables} -N ${forwardChain} 2>/dev/null || ${iptables} -F ${forwardChain}
    for network in \
      0.0.0.0/8 \
      10.0.0.0/8 \
      100.64.0.0/10 \
      127.0.0.0/8 \
      169.254.0.0/16 \
      172.16.0.0/12 \
      192.0.0.0/24 \
      192.0.2.0/24 \
      192.168.0.0/16 \
      198.18.0.0/15 \
      198.51.100.0/24 \
      203.0.113.0/24 \
      224.0.0.0/4 \
      240.0.0.0/4; do
      ${iptables} -A ${forwardChain} -d "$network" -j REJECT
    done
    ${iptables} -A ${forwardChain} -j ACCEPT

    ${iptables} -C INPUT -i pi-veth0 -s ${piNsVethIp}/32 -j ${inputChain} 2>/dev/null \
      || ${iptables} -I INPUT 1 -i pi-veth0 -s ${piNsVethIp}/32 -j ${inputChain}
    ${iptables} -C FORWARD -s ${piNsVethIp}/32 -j ${forwardChain} 2>/dev/null \
      || ${iptables} -I FORWARD 1 -s ${piNsVethIp}/32 -j ${forwardChain}
    ${iptables} -C FORWARD -d ${piNsVethIp}/32 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
      || ${iptables} -I FORWARD 1 -d ${piNsVethIp}/32 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ${iptables} -t nat -C POSTROUTING -s ${piNsVethIp}/32 -j MASQUERADE 2>/dev/null \
      || ${iptables} -t nat -A POSTROUTING -s ${piNsVethIp}/32 -j MASQUERADE

    ${pkgs.coreutils}/bin/install -d -m 0755 /etc/netns/pi
    printf 'nameserver ${piHostVethIp}\n' > /etc/netns/pi/resolv.conf
  '';

  secureNetnsStop = pkgs.writeShellScript "nas-pi-netns-secure-teardown" ''
    set -euo pipefail

    ${iptables} -D INPUT -i pi-veth0 -s ${piNsVethIp}/32 -j ${inputChain} 2>/dev/null || true
    ${iptables} -D FORWARD -s ${piNsVethIp}/32 -j ${forwardChain} 2>/dev/null || true
    ${iptables} -D FORWARD -d ${piNsVethIp}/32 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    ${iptables} -t nat -D POSTROUTING -s ${piNsVethIp}/32 -j MASQUERADE 2>/dev/null || true
    ${iptables} -F ${inputChain} 2>/dev/null || true
    ${iptables} -X ${inputChain} 2>/dev/null || true
    ${iptables} -F ${forwardChain} 2>/dev/null || true
    ${iptables} -X ${forwardChain} 2>/dev/null || true

    ${pkgs.coreutils}/bin/rm -f /etc/netns/pi/resolv.conf
    ${pkgs.coreutils}/bin/rmdir /etc/netns/pi 2>/dev/null || true
    ${ip} netns del pi 2>/dev/null || true
    ${ip} link del pi-veth0 2>/dev/null || true
  '';
in
{
  config = lib.mkIf (ai.enable && code.enable && piPackageAvailable) {
    systemd.services.nas-pi-netns.serviceConfig = {
      ExecStart = lib.mkForce secureNetnsStart;
      ExecStop = lib.mkForce secureNetnsStop;
    };
  };
}
