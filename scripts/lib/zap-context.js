function classifyObservation(rule, uri, parameter, evidence, otherInfo, origin) {
    // Compare the complete origin before discarding queries, which can contain credentials.
    if (!uri.startsWith(origin + "/")) return null;
    const path = uri.slice(origin.length).split(/[?#]/, 1)[0];
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
            String(alert.getEvidence()), String(alert.getOtherInfo()), nasScanOrigin);
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
