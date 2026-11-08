function classifyObservation(rule, uri, parameter, evidence, otherInfo, origin, authenticated) {
    // Compare the complete origin before discarding queries, which can contain credentials.
    if (!uri.startsWith(origin + "/")) return null;
    const path = uri.slice(origin.length).split(/[?#]/, 1)[0];
    // On an HTTPS target rule 40025 first sends a plaintext request to the TLS
    // port as a blind-spot probe. Its 400 rejection differs from the normal HTTPS
    // status, so the rule reports a second, unidentifiable node. Require the exact
    // two-unknown-node report; fingerprinted, silent, and TRACE-enabled findings
    // keep their risk.
    if (rule === 40025 && origin.startsWith("https://") && evidence === "" &&
        otherInfo === "Using the TRACE, OPTIONS, and TRACK methods, the following proxy servers have been identified between ZAP and the application/web server:\n- Unknown\nThe following web/application server has been identified:\n- Unknown\n") {
        return "ZAP's plaintext-on-TLS blind-spot probe after the edge rejected TRACE, TRACK and Max-Forwards OPTIONS";
    }
    if (rule === 10010 && path === "/identity/api/v3/flows/executor/default-authentication-flow/" &&
        parameter === "authentik_csrf" && evidence === "Set-Cookie: authentik_csrf") {
        return "Authentik's CSRF request header requires its JavaScript-readable CSRF cookie";
    }
    if (rule === 2 && path === "/console/cockpit/@localhost/network/networkmanager.js" && evidence === "10.0.0.1") {
        return "Cockpit's static network editor example address";
    }
    if (rule === 10096 && ["/console/cockpit/@localhost/podman/index.js", "/console/cockpit/@localhost/system/terminal.js"].includes(path) &&
        ["1518500249", "1732584193", "1859775393"].includes(evidence)) {
        return "SHA-1 algorithm constant in Cockpit's bundled JavaScript";
    }
    if (rule === 110006 && authenticated === true && path === "/console/cockpit/socket") {
        const ip = evidence.split(".").map(Number);
        if (!/^\d+\.\d+\.\d+\.\d+$/.test(evidence) || ip.some(octet => octet > 255) ||
            !(ip[0] === 10 || (ip[0] === 172 && ip[1] >= 16 && ip[1] <= 31) || (ip[0] === 192 && ip[1] === 168))) return null;
        const message = otherInfo.match(/^\[WebSocket Message\] [0-9]+:[0-9]+![0-9]+\n([\s\S]*)$/);
        if (!message) return null;
        function contains(value) {
            if (typeof value === "string") return value.includes(evidence);
            return value !== null && typeof value === "object" && Object.entries(value).some(([key, item]) =>
                key.includes(evidence) || contains(item));
        }
        let notification;
        try { notification = JSON.parse(message[1]); } catch (_) { notification = null; }
        if (notification && Object.keys(notification).length === 1 && notification.notify &&
            typeof notification.notify === "object" && !Array.isArray(notification.notify)) {
            let found = false;
            for (const [object, interfaces] of Object.entries(notification.notify)) {
                if (!/^\/org\/freedesktop\/NetworkManager(?:\/[A-Za-z0-9_]+)*$/.test(object) ||
                    !interfaces || typeof interfaces !== "object") return null;
                for (const [iface, properties] of Object.entries(interfaces)) {
                    if (iface.includes(evidence) || !properties || typeof properties !== "object") return null;
                    for (const [property, value] of Object.entries(properties)) {
                        if (!contains(value) && !property.includes(evidence)) continue;
                        const prefix = "org.freedesktop.NetworkManager.";
                        const allowed = (iface === prefix + "IP4Config" && ["AddressData", "Gateway", "RouteData", "NameserverData"].includes(property)) ||
                            (iface === prefix + "DnsManager" && property === "Configuration") ||
                            (iface === prefix + "DHCP4Config" && property === "Options" && value && typeof value === "object" &&
                                Object.entries(value).every(([name, item]) => !name.includes(evidence) && (!contains(item) ||
                                    ["dhcp_server_identifier", "domain_name_servers", "ip_address", "next_server", "routers"].includes(name))));
                        if (!allowed) return null;
                        found = true;
                    }
                }
            }
            if (found) return "Authenticated Cockpit NetworkManager address, route, or DNS properties";
        }
        // Cockpit streams journal JSON lines across frame boundaries; every matching line must be complete.
        const lines = message[1].split("\n").filter(line => line.includes(evidence));
        if (lines.length && lines.every(line => {
            let entry;
            try { entry = JSON.parse(line); } catch (_) { return false; }
            return entry && entry._SYSTEMD_UNIT === "firewalld.service" && entry.SYSLOG_IDENTIFIER === "firewalld" &&
                typeof entry.MESSAGE === "string" && /^ERROR: UNKNOWN_SOURCE: '[0-9.]+\/(?:[0-9]|[12][0-9]|3[0-2])' is not in any zone$/.test(entry.MESSAGE) &&
                entry.MESSAGE.includes("'" + evidence + "/") &&
                Object.entries(entry).every(([key, value]) => !key.includes(evidence) && (key === "MESSAGE" || !contains(value)));
        })) return "Authenticated Cockpit journal records of firewalld's unassigned-source diagnostic";
        return null;
    }
    if (rule !== 110005 || path !== "/console/cockpit/socket" || !/^\d+$/.test(evidence)) return null;
    const frame = otherInfo.match(/^\[WebSocket Message\] [0-9]+:[0-9]+![0-9]+\n(\[[\s\S]*\])$/);
    if (!frame) return null;
    let payload;
    try { payload = JSON.parse(frame[1]); } catch (_) { return null; }
    function numericArray(value) {
        return Array.isArray(value) && value.length > 0 && value.every(item =>
            Array.isArray(item) ? numericArray(item) : typeof item === "number" && Number.isFinite(item));
    }
    if (!numericArray(payload)) return null;
    // The PII rule matches a substring of a fractional metric, not a complete number.
    const tokens = frame[1].match(/-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g) || [];
    if (!tokens.some(token => token.includes(".") && token.split(".")[1].split(/[eE]/)[0].includes(evidence))) return null;
    if (tokens.some(token => token === evidence)) return null;
    return "PII digit match occurs only inside the fractional part of a numeric Cockpit metrics frame";
}

if (typeof Java !== "undefined") {
    const nasControl = Java.type("org.parosproxy.paros.control.Control").getSingleton();
    const extension = nasControl.getExtensionLoader().getExtension("ExtensionAlert");
    function classifyAlert(alert) {
        if (alert.getRisk() <= 0) return;
        const reason = classifyObservation(alert.getPluginId(), String(alert.getUri()), String(alert.getParam()),
            String(alert.getEvidence()), String(alert.getOtherInfo()), nasScanOrigin,
            typeof nasAuthenticatedScan !== "undefined" && nasAuthenticatedScan === true);
        if (reason !== null) {
            const originalRisk = alert.getRisk();
            alert.setRisk(0);
            alert.setOtherInfo("NAS contextual classification (original risk " + originalRisk + "): " + reason + "\n" + alert.getOtherInfo());
            extension.updateAlert(alert);
        }
    }
    const alerts = extension.getAllAlerts();
    for (let index = 0; index < alerts.size(); index++) classifyAlert(alerts.get(index));
    // The native exitStatus job reads cached job results rather than the alert database.
    const automation = nasControl.getExtensionLoader().getExtension("ExtensionAutomation");
    const plans = automation.getRunningPlans();
    for (let index = 0; index < plans.size(); index++) {
        const results = plans.get(index).getProgress().getAllJobResultData().iterator();
        while (results.hasNext()) {
            const cachedAlerts = results.next().getAllAlertData().iterator();
            while (cachedAlerts.hasNext()) classifyAlert(cachedAlerts.next());
        }
    }
}
