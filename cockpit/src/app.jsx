import React, {useCallback, useEffect, useMemo, useState} from "react";
import {
  Alert,
  AlertActionCloseButton,
  Button,
  Card,
  CardBody,
  CardTitle,
  Checkbox,
  CodeBlock,
  CodeBlockCode,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Form,
  FormGroup,
  FormSelect,
  FormSelectOption,
  Gallery,
  Grid,
  GridItem,
  Label,
  List,
  ListItem,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  Page,
  PageSection,
  Spinner,
  Stack,
  StackItem,
  TextArea,
  TextInput,
  Title,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
} from "@patternfly/react-core";
import {api, apiInput, activateSecrets, startFirstRun} from "./api.js";
import {
  CAPABILITIES,
  LINK_LABELS,
  MODE_LABELS,
  enabledLinkKeys,
  featureMap,
  featureRuntimeText,
  featureUnitState,
  inactiveServiceCount,
  featureOperationsBusy,
  mib,
  operationBusy,
  revisionModel,
  setupModel,
  safeInternalPath,
  visibleOperations,
} from "./view-model.js";

function errorText(error) {
  return error instanceof Error ? error.message : String(error);
}

function statusVariant(value) {
  return ["active", "enabled", "static", true].includes(value) ? "green" : "red";
}

function StatusLabel({value, children}) {
  return <Label color={statusVariant(value)}>{children ?? value ?? "unknown"}</Label>;
}

function Output({children, ariaLabel}) {
  if (!children) return null;
  return (
    <CodeBlock className="nas-code-output" tabIndex={0} role="region" aria-label={ariaLabel}>
      <CodeBlockCode aria-label={ariaLabel}>{children}</CodeBlockCode>
    </CodeBlock>
  );
}

function Notice({notice, onClose}) {
  if (!notice) return null;
  return (
    <Alert
      variant={notice.variant}
      title={notice.title}
      actionClose={<AlertActionCloseButton onClose={onClose} />}
      isInline
    >
      {notice.message}
    </Alert>
  );
}

function FirstStartPanel({model, onComplete, setNotice}) {
  const [password, setPassword] = useState("");
  const [destructive, setDestructive] = useState(false);
  const [confirmPasswordReapply, setConfirmPasswordReapply] = useState(false);
  const [running, setRunning] = useState(false);
  const [output, setOutput] = useState("");

  const submit = async (event) => {
    event.preventDefault();
    if (model.destructiveRequired && !destructive) {
      setNotice({
        variant: "danger",
        title: "Confirmation required",
        message: "Confirm the destructive storage plan before continuing.",
      });
      return;
    }
    setRunning(true);
    setOutput("Running resumable first-start setup…\n");
    try {
      const process = startFirstRun(password, {
        allowDestructiveStorage: model.destructiveRequired && destructive,
        planDigest: model.planDigest,
        confirmPasswordReapply,
      });
      setPassword("");
      const result = await process;
      setOutput(
        (current) =>
          `${current}Setup job ${result.operationId || "unknown"} ${result.status || "started"}. Progress will continue in systemd and the setup journal.\n`,
      );
      setNotice({
        variant: "info",
        title: "First-start setup started",
        message: "The job continues independently; this page will follow its journal progress.",
      });
      await onComplete();
    } catch (error) {
      setPassword("");
      const message = errorText(error);
      setOutput((current) => `${current}${message}\n`);
      setNotice({variant: "danger", title: "First-start setup failed", message});
    } finally {
      setRunning(false);
    }
  };

  const devices = Array.isArray(model.storage.devices) ? model.storage.devices : [];
  return (
    <PageSection>
      <Card isFullHeight>
        <CardTitle>
          <Title headingLevel="h2">Finish first-start setup</Title>
        </CardTitle>
        <CardBody>
          <Stack hasGutter>
            <StackItem>
              <p className="nas-muted">{model.message}</p>
            </StackItem>
            {model.ready && (
              <StackItem>
                <DescriptionList isHorizontal>
                  <DescriptionListGroup>
                    <DescriptionListTerm>Configuration</DescriptionListTerm>
                    <DescriptionListDescription>
                      <code>{model.configPath || "unknown"}</code>
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                  <DescriptionListGroup>
                    <DescriptionListTerm>Storage</DescriptionListTerm>
                    <DescriptionListDescription>
                      {model.storage.pool || "unknown"} / {model.storage.dataset || "unknown"} ·{" "}
                      {model.storage.topology || "unknown"}
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                  <DescriptionListGroup>
                    <DescriptionListTerm>Initial accounts and services</DescriptionListTerm>
                    <DescriptionListDescription>
                      {model.accountCount} accounts · {model.featureCount} service policies
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                  <DescriptionListGroup>
                    <DescriptionListTerm>Plan fingerprint</DescriptionListTerm>
                    <DescriptionListDescription>
                      <code>{model.planDigest || "unavailable"}</code>
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                </DescriptionList>
                {devices.length > 0 && (
                  <List className="nas-device-list" isPlain>
                    {devices.map((device) => (
                      <ListItem key={device}>
                        <code>{device}</code>
                      </ListItem>
                    ))}
                  </List>
                )}
              </StackItem>
            )}
            {model.journal && (
              <StackItem>
                <Alert
                  variant={model.journal.status === "manual-recovery-required" ? "danger" : "info"}
                  title={`Setup journal: ${model.journal.status || "unknown"}`}
                  isInline
                >
                  {model.journal.currentStep ? `Current stage: ${model.journal.currentStep}. ` : ""}
                  {model.journal.error ||
                    "The setup journal is authoritative for resume and recovery state."}
                </Alert>
              </StackItem>
            )}
            <StackItem>
              <Form className="nas-password-form" onSubmit={submit}>
                <FormGroup
                  label="KeePassXC database password"
                  isRequired
                  fieldId="first-start-password"
                >
                  <TextInput
                    id="first-start-password"
                    value={password}
                    type="password"
                    autoComplete="current-password"
                    onChange={(_event, value) => setPassword(value)}
                    isRequired
                    maxLength={4096}
                  />
                </FormGroup>
                {model.destructiveRequired && (
                  <Checkbox
                    id="first-start-destructive"
                    label="I understand that the listed storage devices will be used to create the configured ZFS pool and existing data on them may be destroyed."
                    isChecked={destructive}
                    onChange={(_event, checked) => setDestructive(checked)}
                  />
                )}
                <Checkbox
                  id="first-start-password-reapply"
                  label="If this resumes an interrupted identity stage, repeat the configured account password changes"
                  isChecked={confirmPasswordReapply}
                  onChange={(_event, checked) => setConfirmPasswordReapply(checked)}
                />
                <Button
                  type="submit"
                  variant="primary"
                  isDisabled={!model.ready || running || !password || !model.planDigest}
                  isLoading={running}
                >
                  Start setup
                </Button>
              </Form>
            </StackItem>
            <StackItem>
              <Output ariaLabel="First-start setup output">{output}</Output>
            </StackItem>
            <StackItem>
              <p className="nas-muted">
                The password is sent only over standard input to the privileged setup process. Setup
                is journaled and resumes completed stages after an interruption.
              </p>
            </StackItem>
          </Stack>
        </CardBody>
      </Card>
    </PageSection>
  );
}

function UnlockPanel({model, onComplete, setNotice}) {
  const [password, setPassword] = useState("");
  const [running, setRunning] = useState(false);
  const [output, setOutput] = useState("");

  const submit = async (event) => {
    event.preventDefault();
    setRunning(true);
    setOutput("Starting protected services…\n");
    try {
      const process = activateSecrets(password);
      setPassword("");
      if (typeof process.stream === "function") {
        process.stream((chunk) => setOutput((current) => current + chunk));
      }
      await process;
      setOutput((current) => `${current}\nUnlock completed. Refreshing status…\n`);
      setNotice({
        variant: "success",
        title: "NAS unlocked",
        message: "Protected storage and services started successfully.",
      });
      await onComplete();
    } catch (error) {
      setPassword("");
      const message = errorText(error);
      setOutput((current) => `${current}\n${message}\n`);
      setNotice({variant: "danger", title: "Unlock failed", message});
    } finally {
      setRunning(false);
    }
  };

  return (
    <PageSection>
      <Card>
        <CardTitle>
          <Title headingLevel="h2">Unlock protected storage and services</Title>
        </CardTitle>
        <CardBody>
          <Stack hasGutter>
            <StackItem>
              <p className="nas-muted">
                Cockpit remains available as the recovery interface while KeePassXC and encrypted
                ZFS are locked. The password is written only to{" "}
                <code>nas-secrets activate-stdin</code> over process standard input.
              </p>
            </StackItem>
            {model.journal && (
              <StackItem>
                <Alert
                  variant={model.journal.status === "manual-recovery-required" ? "danger" : "info"}
                  title={`Setup journal: ${model.journal.status || "unknown"}`}
                  isInline
                >
                  {model.journal.currentStep ? `Current stage: ${model.journal.currentStep}. ` : ""}
                  {model.journal.error ||
                    "The setup journal is authoritative for resume and recovery state."}
                </Alert>
              </StackItem>
            )}
            <StackItem>
              <Form className="nas-password-form" onSubmit={submit}>
                <FormGroup label="KeePassXC database password" isRequired fieldId="unlock-password">
                  <TextInput
                    id="unlock-password"
                    value={password}
                    type="password"
                    autoComplete="off"
                    onChange={(_event, value) => setPassword(value)}
                    isRequired
                    maxLength={4096}
                  />
                </FormGroup>
                <Button
                  type="submit"
                  variant="primary"
                  isDisabled={running || !password}
                  isLoading={running}
                >
                  Unlock NAS
                </Button>
              </Form>
            </StackItem>
            <StackItem>
              <Output ariaLabel="Unlock output">{output}</Output>
            </StackItem>
            <StackItem>
              <p className="nas-muted">
                Sign in with the local Linux/Cockpit administrator. Authentik accounts are
                unavailable until Authentik itself is unlocked and started.
              </p>
            </StackItem>
          </Stack>
        </CardBody>
      </Card>
    </PageSection>
  );
}

function SummaryCards({data}) {
  const revision = revisionModel(data.update || {});
  const memory = data.featureControl?.memory;
  const resident = memory?.residentEstimateMiB || memory?.estimateMiB || {};
  const active = memory?.activeEstimateMiB || resident;
  const configured = memory?.configuredMaximumMiB || resident;
  const savings = memory?.onDemandSavingsMiB || {};
  const identity = data.identity || {};

  return (
    <PageSection>
      <Gallery hasGutter minWidths={{default: "19rem"}}>
        <Card className="nas-summary-card">
          <CardTitle>System lock state</CardTitle>
          <CardBody className="nas-status-stack">
            <StatusLabel value={Boolean(data.protectedReady)}>
              {data.protectedReady ? "Ready" : "Locked"}
            </StatusLabel>
            <p>{inactiveServiceCount(data.services)} inactive listed services</p>
            {data.authentikTokenWarning && (
              <Alert variant="warning" title="Authentik token warning" isInline>
                {data.authentikTokenWarning}
              </Alert>
            )}
          </CardBody>
        </Card>
        <Card className="nas-summary-card">
          <CardTitle>Identity and access</CardTitle>
          <CardBody className="nas-status-stack">
            {identity.ok === false || !data.identity ? (
              <>
                <StatusLabel value={false}>Unavailable</StatusLabel>
                <p>{identity.error || "Authentik is locked or offline"}</p>
              </>
            ) : (
              <>
                <StatusLabel value>Available</StatusLabel>
                <p>
                  {identity.users?.length ?? 0} users, {identity.groups?.length ?? 0} groups
                </p>
                <p>
                  Trusted administrators: {(identity.administrators || []).join(", ") || "none"}
                </p>
                <p>Share authority: {identity.shareAuthority || "CopyParty"}</p>
              </>
            )}
          </CardBody>
        </Card>
        <Card className="nas-summary-card">
          <CardTitle>Source revision</CardTitle>
          <CardBody className="nas-status-stack">
            {revision.kind === "error" ? (
              <>
                <StatusLabel value={false}>Inspection failed</StatusLabel>
                <p>{revision.error}</p>
              </>
            ) : (
              <>
                <code>{revision.revision}</code>
                <p>Branch: {revision.branch}</p>
                <p>Upstream: {revision.upstream}</p>
                <p>{revision.divergence}</p>
                <StatusLabel value={revision.checkout === "clean"}>
                  {revision.checkout === "dirty"
                    ? "Uncommitted changes"
                    : revision.checkout === "clean"
                      ? "Clean checkout"
                      : "Checkout state unavailable"}
                </StatusLabel>
              </>
            )}
          </CardBody>
        </Card>
        <Card className="nas-summary-card">
          <CardTitle>Memory footprint</CardTitle>
          <CardBody className="nas-status-stack">
            {!memory ? (
              <StatusLabel value={false}>Unavailable</StatusLabel>
            ) : (
              <>
                <strong>{resident.typical ?? "—"} MiB resident typical</strong>
                <p>
                  {resident.min ?? "—"}–{resident.max ?? "—"} MiB steady-state fixed userspace
                </p>
                <p>Active now: ~{active.typical ?? "—"} MiB</p>
                <p>All configured apps awake: ~{configured.typical ?? "—"} MiB</p>
                <p>On-demand savings: ~{savings.typical ?? 0} MiB</p>
                <p>{mib(memory.system?.availableBytes)} MiB currently available</p>
              </>
            )}
          </CardBody>
        </Card>
      </Gallery>
    </PageSection>
  );
}

function FeatureGrid({data, busyFeature, onModeChange}) {
  const operationsBusy = featureOperationsBusy(data);
  const features = data.featureControl?.features || [];
  return (
    <PageSection>
      <Title headingLevel="h2" className="nas-section-heading">
        Service policies
      </Title>
      <p className="nas-muted nas-section-heading">
        Choose how optional services run. On-demand services wake for authorized use and sleep after
        their idle period; NixOS still controls what is installed.
      </p>
      {!features.length ? (
        <Alert variant="warning" title="Feature catalog unavailable" isInline>
          {data.featureControl?.error || "No feature data was returned."}
        </Alert>
      ) : (
        <Gallery hasGutter minWidths={{default: "20rem"}}>
          {features.map((feature) => {
            const runtime = featureRuntimeText(feature);
            return (
              <Card
                key={feature.id}
                className={`nas-feature-card ${feature.effective ? "nas-feature-card--enabled" : ""}`}
              >
                <CardTitle>{feature.label}</CardTitle>
                <CardBody>
                  <Stack hasGutter>
                    <StackItem>
                      <p>
                        {feature.description}
                        {feature.parent ? ` Depends on ${feature.parent}.` : ""}
                      </p>
                    </StackItem>
                    <StackItem>
                      <FormGroup label="Runtime policy" fieldId={`feature-${feature.id}`}>
                        <FormSelect
                          id={`feature-${feature.id}`}
                          value={feature.requestedMode}
                          onChange={(_event, value) => onModeChange(feature.id, value)}
                          isDisabled={
                            !feature.available || busyFeature === feature.id || operationsBusy
                          }
                          aria-label={`${feature.label} runtime policy`}
                        >
                          {(feature.allowedModes || ["off", "always"]).map((mode) => (
                            <FormSelectOption
                              key={mode}
                              value={mode}
                              label={MODE_LABELS[mode] || mode}
                            />
                          ))}
                        </FormSelect>
                      </FormGroup>
                    </StackItem>
                    <StackItem className="nas-feature-labels">
                      <Label color={feature.available ? "green" : "grey"}>
                        {feature.available ? "Installed" : "Not installed"}
                      </Label>
                      <Label color={feature.runtimeAvailable === false ? "red" : "green"}>
                        {feature.runtimeAvailable === false
                          ? "Runtime unavailable"
                          : "Runtime available"}
                      </Label>
                      <Label color="blue">
                        {MODE_LABELS[feature.effectiveMode] || feature.effectiveMode}
                      </Label>
                      <Label color={feature.running ? "green" : "grey"}>
                        {featureUnitState(feature)}
                      </Label>
                    </StackItem>
                    {runtime && (
                      <StackItem>
                        <small className="nas-muted">{runtime}</small>
                      </StackItem>
                    )}
                  </Stack>
                </CardBody>
              </Card>
            );
          })}
        </Gallery>
      )}
    </PageSection>
  );
}

function CapabilityTable({data}) {
  const value = data.capabilities;
  return (
    <PageSection>
      <Toolbar className="nas-section-heading">
        <ToolbarContent>
          <ToolbarItem variant="label">
            <Title headingLevel="h2">User access</Title>
          </ToolbarItem>
          <ToolbarItem align={{default: "alignEnd"}}>
            <Button
              component="a"
              href="/identity/"
              target="_blank"
              rel="noopener noreferrer"
              variant="secondary"
            >
              Open Authentik
            </Button>
          </ToolbarItem>
        </ToolbarContent>
      </Toolbar>
      <p className="nas-muted nas-section-heading">
        Access comes from Authentik groups. Use Authentik to change memberships, MFA, and
        application policy; this view is read-only.
      </p>
      {!value || value.ok === false ? (
        <Alert variant="danger" title="Capability data unavailable" isInline>
          {value?.error || "No capability data was returned."}
        </Alert>
      ) : (
        <div className="nas-table-wrap" tabIndex={0} role="region" aria-label="User access">
          <table
            className="pf-v6-c-table pf-m-grid-md nas-table"
            role="grid"
            aria-label="User access"
          >
            <thead>
              <tr>
                <th>User</th>
                {CAPABILITIES.map(([, label]) => (
                  <th key={label}>{label}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {(value.users || []).length === 0 ? (
                <tr>
                  <td colSpan={CAPABILITIES.length + 1}>No human Authentik users found.</td>
                </tr>
              ) : (
                (value.users || []).map((user) => (
                  <tr key={user.id}>
                    <td data-label="User">
                      <strong>{user.displayName || user.id}</strong>
                      <br />
                      <code>{user.id}</code>
                      {user.administrator && (
                        <>
                          <br />
                          <Label color="blue">Administrator</Label>
                        </>
                      )}
                    </td>
                    {CAPABILITIES.map(([capability, label]) => {
                      const current = user.capabilities?.[capability] || {};
                      return (
                        <td key={capability} data-label={label}>
                          <StatusLabel value={Boolean(current.allowed)}>
                            {current.allowed ? "Allowed" : "Denied"}
                          </StatusLabel>
                          <br />
                          <small>{current.source || "default"}</small>
                        </td>
                      );
                    })}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}
    </PageSection>
  );
}

function MemoryTable({data}) {
  const memory = data.featureControl?.memory;
  return (
    <PageSection>
      <Title headingLevel="h2" className="nas-section-heading">
        Memory planner
      </Title>
      <p className="nas-muted nas-section-heading">
        Estimates show fixed userspace memory with no AI model loaded. Current values use systemd
        accounting when available; adaptive ZFS ARC cache is not included.
      </p>
      {!memory ? (
        <Alert variant="warning" title="Memory model unavailable" isInline />
      ) : (
        <div className="nas-table-wrap" tabIndex={0} role="region" aria-label="Memory planner">
          <table
            className="pf-v6-c-table pf-m-grid-md nas-table"
            role="grid"
            aria-label="Memory planner"
          >
            <thead>
              <tr>
                <th>Component</th>
                <th>Policy</th>
                <th>Resident</th>
                <th>Predicted MiB</th>
                <th>Current MiB</th>
                <th>Notes</th>
              </tr>
            </thead>
            <tbody>
              {(memory.components || []).map((component) => (
                <tr
                  key={component.id || component.label}
                  className={component.configured ? "" : "nas-table__excluded"}
                >
                  <td data-label="Component">
                    <strong>{component.label}</strong>
                  </td>
                  <td data-label="Policy">{component.mode || "core"}</td>
                  <td data-label="Resident">
                    <StatusLabel value={Boolean(component.resident)}>
                      {component.resident ? "Yes" : "No"}
                    </StatusLabel>
                  </td>
                  <td data-label="Predicted MiB">
                    {component.estimateMiB.min}–{component.estimateMiB.max}
                    <br />
                    <small>typical {component.estimateMiB.typical}</small>
                  </td>
                  <td data-label="Current MiB">{mib(component.currentBytes)}</td>
                  <td data-label="Notes">{component.notes || ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </PageSection>
  );
}

const AI_PROVIDER_PRESETS = {
  custom: {label: "Custom OpenAI-compatible", id: "", url: ""},
  openrouter: {label: "OpenRouter", id: "openrouter", url: "https://openrouter.ai/api"},
  openai: {label: "OpenAI", id: "openai", url: "https://api.openai.com"},
  groq: {label: "Groq", id: "groq", url: "https://api.groq.com/openai"},
  deepseek: {label: "DeepSeek", id: "deepseek", url: "https://api.deepseek.com"},
};

const CODING_ROLE_LABELS = {
  "coding/default": "Default coding agent",
  "coding/cheap": "Economy worker",
  "coding/planner": "Planner",
  "coding/reviewer": "Reviewer",
  "coding/research": "Researcher",
  "coding/local-worker": "Local bounded worker",
};

function lines(value) {
  return String(value || "")
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function numberOr(value, fallback) {
  const parsed = Number.parseInt(String(value), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function argvLines(value) {
  return String(value || "")
    .split(/\n/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function AIConfiguration({data, onRefresh, setNotice}) {
  const config = data.aiConfig || {};
  const [preset, setPreset] = useState("custom");
  const [providerId, setProviderId] = useState("");
  const [providerUrl, setProviderUrl] = useState("");
  const [providerModels, setProviderModels] = useState("");
  const [providerKey, setProviderKey] = useState("");
  const [keepassPassword, setKeepassPassword] = useState("");
  const [connectTimeout, setConnectTimeout] = useState("30");
  const [keepaliveTimeout, setKeepaliveTimeout] = useState("30");
  const [responseTimeout, setResponseTimeout] = useState("60");
  const [tlsTimeout, setTlsTimeout] = useState("10");
  const [idleTimeout, setIdleTimeout] = useState("90");
  const [stripParams, setStripParams] = useState("");
  const [setParams, setSetParams] = useState("{}");
  const [providerBusy, setProviderBusy] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [localModelId, setLocalModelId] = useState("");
  const [localModelPath, setLocalModelPath] = useState("");
  const [localContext, setLocalContext] = useState("32768");
  const [localTtl, setLocalTtl] = useState("300");
  const [localTools, setLocalTools] = useState(true);
  const [localArgs, setLocalArgs] = useState("");
  const [localBusy, setLocalBusy] = useState(false);
  const [localDeleteTarget, setLocalDeleteTarget] = useState(null);
  const [roleBusy, setRoleBusy] = useState(null);
  const [advancedBusy, setAdvancedBusy] = useState(false);
  const [advanced, setAdvanced] = useState({
    healthCheckTimeout: String(config.advanced?.healthCheckTimeout ?? 300),
    globalTTL: String(config.advanced?.globalTTL ?? 300),
    unloadTimeout: String(config.advanced?.unloadTimeout ?? 10),
    logLevel: String(config.advanced?.logLevel ?? "info"),
    captureBuffer: String(config.advanced?.captureBuffer ?? 0),
    metricsMaxInMemory: String(config.advanced?.metricsMaxInMemory ?? 250),
  });
  const [roles, setRoles] = useState(() =>
    Object.fromEntries(
      Object.keys(CODING_ROLE_LABELS).map((role) => {
        const current = config.codingRoles?.[role] || {};
        return [
          role,
          {
            targets: (current.targets || []).join("\n"),
            strategy: current.strategy || "warm",
            spillover: String(current.spillover ?? 1),
          },
        ];
      }),
    ),
  );

  const advancedSignature = JSON.stringify(config.advanced || {});
  const rolesSignature = JSON.stringify(config.codingRoles || {});

  useEffect(() => {
    setAdvanced({
      healthCheckTimeout: String(config.advanced?.healthCheckTimeout ?? 300),
      globalTTL: String(config.advanced?.globalTTL ?? 300),
      unloadTimeout: String(config.advanced?.unloadTimeout ?? 10),
      logLevel: String(config.advanced?.logLevel ?? "info"),
      captureBuffer: String(config.advanced?.captureBuffer ?? 0),
      metricsMaxInMemory: String(config.advanced?.metricsMaxInMemory ?? 250),
    });
    setRoles(
      Object.fromEntries(
        Object.keys(CODING_ROLE_LABELS).map((role) => {
          const current = config.codingRoles?.[role] || {};
          return [
            role,
            {
              targets: (current.targets || []).join("\n"),
              strategy: current.strategy || "warm",
              spillover: String(current.spillover ?? 1),
            },
          ];
        }),
      ),
    );
    // Polling returns fresh objects; only reset form state when values actually changed.
  }, [advancedSignature, rolesSignature]);

  const applyPreset = (value) => {
    setPreset(value);
    const selected = AI_PROVIDER_PRESETS[value];
    if (selected && value !== "custom") {
      setProviderId(selected.id);
      setProviderUrl(selected.url);
    }
  };

  const editProvider = (provider) => {
    setPreset(Object.hasOwn(AI_PROVIDER_PRESETS, provider.id) ? provider.id : "custom");
    setProviderId(provider.id || "");
    setProviderUrl(provider.url || "");
    setProviderModels((provider.models || []).join("\n"));
    setProviderKey("");
    setKeepassPassword("");
    setConnectTimeout(String(provider.timeouts?.connect ?? 30));
    setKeepaliveTimeout(String(provider.timeouts?.keepalive ?? 30));
    setResponseTimeout(String(provider.timeouts?.responseHeader ?? 60));
    setTlsTimeout(String(provider.timeouts?.tlsHandshake ?? 10));
    setIdleTimeout(String(provider.timeouts?.idleConn ?? 90));
    setStripParams(provider.filters?.stripParams || "");
    setSetParams(JSON.stringify(provider.filters?.setParams || {}, null, 2));
  };

  const saveProvider = async (event) => {
    event.preventDefault();
    setProviderBusy(true);
    try {
      let parsedSetParams;
      try {
        parsedSetParams = JSON.parse(setParams || "{}");
      } catch (_error) {
        throw new Error("Provider setParams must be valid JSON.");
      }
      await apiInput(["ai-provider-set"], {
        id: providerId.trim(),
        url: providerUrl.trim(),
        models: lines(providerModels),
        apiKey: providerKey,
        keepassPassword,
        timeouts: {
          connect: numberOr(connectTimeout, 30),
          keepalive: numberOr(keepaliveTimeout, 30),
          responseHeader: numberOr(responseTimeout, 60),
          tlsHandshake: numberOr(tlsTimeout, 10),
          idleConn: numberOr(idleTimeout, 90),
        },
        filters: {stripParams: stripParams.trim(), setParams: parsedSetParams},
      });
      setProviderKey("");
      setKeepassPassword("");
      setNotice({
        variant: "success",
        title: "AI provider saved",
        message: `${providerId} is now routed through llama-swap.`,
      });
      await onRefresh({quiet: true});
    } catch (error) {
      setProviderKey("");
      setKeepassPassword("");
      setNotice({variant: "danger", title: "AI provider update failed", message: errorText(error)});
    } finally {
      setProviderBusy(false);
    }
  };

  const deleteProvider = async (provider) => {
    if (provider.credentialConfigured && !keepassPassword) {
      setNotice({
        variant: "warning",
        title: "KeePass password required",
        message:
          "Enter the KeePassXC database password in the provider form before deleting a provider with a stored key.",
      });
      return;
    }
    setProviderBusy(true);
    try {
      await apiInput(["ai-provider-delete"], {id: provider.id, keepassPassword});
      setKeepassPassword("");
      if (providerId === provider.id) {
        setProviderId("");
        setProviderUrl("");
        setProviderModels("");
        setProviderKey("");
      }
      setNotice({
        variant: "success",
        title: "AI provider removed",
        message: `${provider.id} and its stored credential reference were removed.`,
      });
      setDeleteTarget(null);
      await onRefresh({quiet: true});
    } catch (error) {
      setKeepassPassword("");
      setNotice({
        variant: "danger",
        title: "AI provider removal failed",
        message: errorText(error),
      });
    } finally {
      setProviderBusy(false);
    }
  };

  const editLocalModel = (model) => {
    if (!model.managed) {
      setNotice({
        variant: "info",
        title: "Manual model",
        message: `${model.id} is defined outside Cockpit and is intentionally read-only here.`,
      });
      return;
    }
    setLocalModelId(model.id || "");
    setLocalModelPath(model.path || "");
    setLocalContext(String(model.context ?? 32768));
    setLocalTtl(String(model.ttl ?? 300));
    setLocalTools(Boolean(model.tools));
    setLocalArgs((model.extraArgs || []).join("\n"));
  };

  const saveLocalModel = async (event) => {
    event.preventDefault();
    setLocalBusy(true);
    try {
      await apiInput(["ai-local-model-set"], {
        id: localModelId.trim(),
        path: localModelPath.trim(),
        context: numberOr(localContext, 32768),
        ttl: numberOr(localTtl, 300),
        tools: localTools,
        extraArgs: argvLines(localArgs),
      });
      setNotice({
        variant: "success",
        title: "Local model saved",
        message: `${localModelId} is available through llama-swap.`,
      });
      await onRefresh({quiet: true});
    } catch (error) {
      setNotice({variant: "danger", title: "Local model update failed", message: errorText(error)});
    } finally {
      setLocalBusy(false);
    }
  };

  const deleteLocalModel = async (model) => {
    setLocalBusy(true);
    try {
      await apiInput(["ai-local-model-delete"], {id: model.id});
      if (localModelId === model.id) {
        setLocalModelId("");
        setLocalModelPath("");
        setLocalArgs("");
      }
      setLocalDeleteTarget(null);
      setNotice({
        variant: "success",
        title: "Local model removed",
        message: `${model.id} was removed from the managed llama-swap configuration.`,
      });
      await onRefresh({quiet: true});
    } catch (error) {
      setNotice({
        variant: "danger",
        title: "Local model removal failed",
        message: errorText(error),
      });
    } finally {
      setLocalBusy(false);
    }
  };

  const saveRole = async (role) => {
    const current = roles[role];
    setRoleBusy(role);
    try {
      await apiInput(["ai-role-set"], {
        role,
        targets: lines(current.targets),
        strategy: current.strategy,
        spillover: numberOr(current.spillover, 1),
      });
      setNotice({
        variant: "success",
        title: "Coding model role saved",
        message: `${role} routing was updated.`,
      });
      await onRefresh({quiet: true});
    } catch (error) {
      setNotice({variant: "danger", title: "Coding role update failed", message: errorText(error)});
    } finally {
      setRoleBusy(null);
    }
  };

  const saveAdvanced = async (event) => {
    event.preventDefault();
    setAdvancedBusy(true);
    try {
      await apiInput(["ai-advanced-set"], {
        healthCheckTimeout: numberOr(advanced.healthCheckTimeout, 300),
        globalTTL: numberOr(advanced.globalTTL, 300),
        unloadTimeout: numberOr(advanced.unloadTimeout, 10),
        logLevel: advanced.logLevel,
        captureBuffer: numberOr(advanced.captureBuffer, 0),
        metricsMaxInMemory: numberOr(advanced.metricsMaxInMemory, 250),
      });
      setNotice({
        variant: "success",
        title: "AI runtime settings saved",
        message: "llama-swap will reload the structured runtime configuration.",
      });
      await onRefresh({quiet: true});
    } catch (error) {
      setNotice({variant: "danger", title: "AI runtime update failed", message: errorText(error)});
    } finally {
      setAdvancedBusy(false);
    }
  };

  return (
    <PageSection>
      <Title headingLevel="h2" className="nas-section-heading">
        AI configuration
      </Title>
      <p className="nas-muted nas-section-heading">
        llama-swap is the single model authority. Configure local/remote model routing here; cloud
        provider keys are written to KeePass and only staged into llama-swap, never Pi or Open
        WebUI.
      </p>
      {!config.ok ? (
        <Alert variant="warning" title="AI runtime configuration unavailable" isInline>
          {config.error || "Enable and unlock the AI runtime first."}
        </Alert>
      ) : (
        <Grid hasGutter>
          <GridItem md={12}>
            <Card>
              <CardTitle>Local llama.cpp models</CardTitle>
              <CardBody>
                <Stack hasGutter>
                  {(config.localModels || []).length > 0 && (
                    <StackItem>
                      <div
                        className="nas-table-wrap"
                        tabIndex={0}
                        role="region"
                        aria-label="Local AI models"
                      >
                        <table
                          className="pf-v6-c-table pf-m-grid-md nas-table"
                          aria-label="Local AI models"
                        >
                          <thead>
                            <tr>
                              <th>Model</th>
                              <th>Source</th>
                              <th>Context</th>
                              <th>TTL</th>
                              <th>Tools</th>
                              <th>Actions</th>
                            </tr>
                          </thead>
                          <tbody>
                            {(config.localModels || []).map((model) => (
                              <tr key={model.id}>
                                <td>
                                  <code>{model.id}</code>
                                </td>
                                <td>
                                  {model.managed ? (
                                    <code>{model.path}</code>
                                  ) : (
                                    <StatusLabel value={true}>Manual config</StatusLabel>
                                  )}
                                </td>
                                <td>{model.managed ? model.context : "—"}</td>
                                <td>{model.managed ? `${model.ttl}s` : "—"}</td>
                                <td>{model.managed ? (model.tools ? "Yes" : "No") : "—"}</td>
                                <td>
                                  {model.managed ? (
                                    <>
                                      <Button variant="link" onClick={() => editLocalModel(model)}>
                                        Edit
                                      </Button>
                                      <Button
                                        variant="link"
                                        isDanger
                                        onClick={() => setLocalDeleteTarget(model)}
                                        isDisabled={localBusy}
                                      >
                                        Delete
                                      </Button>
                                    </>
                                  ) : (
                                    <Button variant="link" onClick={() => editLocalModel(model)}>
                                      Details
                                    </Button>
                                  )}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </StackItem>
                  )}
                  <StackItem>
                    <Form onSubmit={saveLocalModel}>
                      <Grid hasGutter>
                        <GridItem sm={6}>
                          <FormGroup label="Model ID" isRequired fieldId="ai-local-model-id">
                            <TextInput
                              id="ai-local-model-id"
                              value={localModelId}
                              onChange={(_e, value) => setLocalModelId(value)}
                              placeholder="qwen35-9b-q4"
                            />
                          </FormGroup>
                        </GridItem>
                        <GridItem sm={6}>
                          <FormGroup label="GGUF path" isRequired fieldId="ai-local-model-path">
                            <TextInput
                              id="ai-local-model-path"
                              value={localModelPath}
                              onChange={(_e, value) => setLocalModelPath(value)}
                              placeholder="/tank/ai/huggingface/models/model.gguf"
                            />
                          </FormGroup>
                        </GridItem>
                        <GridItem sm={4}>
                          <FormGroup label="Context tokens">
                            <TextInput
                              type="number"
                              min={1024}
                              max={1048576}
                              value={localContext}
                              onChange={(_e, value) => setLocalContext(value)}
                            />
                          </FormGroup>
                        </GridItem>
                        <GridItem sm={4}>
                          <FormGroup label="Idle TTL (seconds)">
                            <TextInput
                              type="number"
                              min={-1}
                              max={604800}
                              value={localTtl}
                              onChange={(_e, value) => setLocalTtl(value)}
                            />
                          </FormGroup>
                        </GridItem>
                        <GridItem sm={4}>
                          <FormGroup label="Capabilities">
                            <Checkbox
                              id="ai-local-tools"
                              label="Tool/function calling"
                              isChecked={localTools}
                              onChange={(_e, value) => setLocalTools(value)}
                            />
                          </FormGroup>
                        </GridItem>
                      </Grid>
                      <FormGroup
                        label="Extra llama-server arguments (one argv item per line)"
                        fieldId="ai-local-model-args"
                      >
                        <TextArea
                          id="ai-local-model-args"
                          value={localArgs}
                          onChange={(_e, value) => setLocalArgs(value)}
                          rows={4}
                          placeholder={"--n-gpu-layers=999\n--flash-attn=on"}
                        />
                      </FormGroup>
                      <p className="nas-muted">
                        Cockpit fixes the server host, port, model path and context flags. Extra
                        arguments are validated as argv entries rather than evaluated as shell text.
                      </p>
                      <Button
                        type="submit"
                        variant="primary"
                        isLoading={localBusy}
                        isDisabled={localBusy || !localModelId || !localModelPath}
                      >
                        Save local model
                      </Button>
                    </Form>
                  </StackItem>
                </Stack>
              </CardBody>
            </Card>
          </GridItem>
          <GridItem md={12} xl={7}>
            <Card isFullHeight>
              <CardTitle>Remote/cloud providers</CardTitle>
              <CardBody>
                <Stack hasGutter>
                  {(config.providers || []).length > 0 && (
                    <StackItem>
                      <div
                        className="nas-table-wrap"
                        tabIndex={0}
                        role="region"
                        aria-label="AI providers"
                      >
                        <table
                          className="pf-v6-c-table pf-m-grid-md nas-table"
                          aria-label="AI providers"
                        >
                          <thead>
                            <tr>
                              <th>Provider</th>
                              <th>Endpoint</th>
                              <th>Models</th>
                              <th>Credential</th>
                              <th>Actions</th>
                            </tr>
                          </thead>
                          <tbody>
                            {(config.providers || []).map((provider) => (
                              <tr key={provider.id}>
                                <td>
                                  <code>{provider.id}</code>
                                </td>
                                <td>
                                  <code>{provider.url}</code>
                                </td>
                                <td>{(provider.models || []).length}</td>
                                <td>
                                  <StatusLabel value={Boolean(provider.credentialConfigured)}>
                                    {provider.credentialConfigured ? "KeePass" : "None"}
                                  </StatusLabel>
                                </td>
                                <td>
                                  <Button variant="link" onClick={() => editProvider(provider)}>
                                    Edit
                                  </Button>
                                  <Button
                                    variant="link"
                                    isDanger
                                    onClick={() => setDeleteTarget(provider)}
                                    isDisabled={providerBusy}
                                  >
                                    Delete
                                  </Button>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </StackItem>
                  )}
                  <StackItem>
                    <Form onSubmit={saveProvider}>
                      <FormGroup label="Provider preset" fieldId="ai-provider-preset">
                        <FormSelect
                          id="ai-provider-preset"
                          value={preset}
                          onChange={(_e, value) => applyPreset(value)}
                        >
                          {Object.entries(AI_PROVIDER_PRESETS).map(([id, value]) => (
                            <FormSelectOption key={id} value={id} label={value.label} />
                          ))}
                        </FormSelect>
                      </FormGroup>
                      <FormGroup label="Provider ID" isRequired fieldId="ai-provider-id">
                        <TextInput
                          id="ai-provider-id"
                          value={providerId}
                          onChange={(_e, value) => setProviderId(value)}
                          placeholder="openrouter"
                        />
                      </FormGroup>
                      <FormGroup
                        label="OpenAI-compatible base URL"
                        isRequired
                        fieldId="ai-provider-url"
                      >
                        <TextInput
                          id="ai-provider-url"
                          value={providerUrl}
                          onChange={(_e, value) => setProviderUrl(value)}
                          placeholder="https://provider.example/api"
                        />
                      </FormGroup>
                      <FormGroup
                        label="Model IDs (one per line)"
                        isRequired
                        fieldId="ai-provider-models"
                      >
                        <TextArea
                          id="ai-provider-models"
                          value={providerModels}
                          onChange={(_e, value) => setProviderModels(value)}
                          rows={6}
                        />
                      </FormGroup>
                      <FormGroup label="Provider API key" fieldId="ai-provider-key">
                        <TextInput
                          id="ai-provider-key"
                          type="password"
                          autoComplete="new-password"
                          value={providerKey}
                          onChange={(_e, value) => setProviderKey(value)}
                          placeholder="Leave blank to keep the existing key"
                        />
                      </FormGroup>
                      <FormGroup label="KeePassXC database password" fieldId="ai-provider-keepass">
                        <TextInput
                          id="ai-provider-keepass"
                          type="password"
                          autoComplete="current-password"
                          value={keepassPassword}
                          onChange={(_e, value) => setKeepassPassword(value)}
                          placeholder="Required only when changing/removing a provider key"
                        />
                      </FormGroup>
                      <Grid hasGutter>
                        {[
                          ["Connect", connectTimeout, setConnectTimeout],
                          ["Keepalive", keepaliveTimeout, setKeepaliveTimeout],
                          ["Response header", responseTimeout, setResponseTimeout],
                          ["TLS handshake", tlsTimeout, setTlsTimeout],
                          ["Idle connection", idleTimeout, setIdleTimeout],
                        ].map(([label, value, setter]) => (
                          <GridItem key={label} sm={6} lg={4}>
                            <FormGroup label={`${label} timeout (s)`}>
                              <TextInput
                                type="number"
                                min={0}
                                max={3600}
                                value={value}
                                onChange={(_e, next) => setter(next)}
                              />
                            </FormGroup>
                          </GridItem>
                        ))}
                      </Grid>
                      <FormGroup label="Strip request parameters" fieldId="ai-provider-strip">
                        <TextInput
                          id="ai-provider-strip"
                          value={stripParams}
                          onChange={(_e, value) => setStripParams(value)}
                          placeholder="temperature, top_p"
                        />
                      </FormGroup>
                      <FormGroup
                        label="Forced request parameters (JSON)"
                        fieldId="ai-provider-set-params"
                      >
                        <TextArea
                          id="ai-provider-set-params"
                          value={setParams}
                          onChange={(_e, value) => setSetParams(value)}
                          rows={5}
                        />
                      </FormGroup>
                      <Button
                        type="submit"
                        variant="primary"
                        isLoading={providerBusy}
                        isDisabled={
                          providerBusy ||
                          !providerId ||
                          !providerUrl ||
                          lines(providerModels).length === 0
                        }
                      >
                        Save provider
                      </Button>
                    </Form>
                  </StackItem>
                </Stack>
              </CardBody>
            </Card>
          </GridItem>
          <GridItem md={12} xl={5}>
            <Stack hasGutter>
              <StackItem>
                <Card>
                  <CardTitle>Coding-agent model roles</CardTitle>
                  <CardBody>
                    <Stack hasGutter>
                      {Object.entries(CODING_ROLE_LABELS).map(([role, label]) => {
                        const current = roles[role] || {
                          targets: "",
                          strategy: "warm",
                          spillover: "1",
                        };
                        return (
                          <StackItem key={role}>
                            <Form>
                              <FormGroup label={label} fieldId={`role-${role}`}>
                                <TextArea
                                  id={`role-${role}`}
                                  value={current.targets}
                                  onChange={(_e, value) =>
                                    setRoles((old) => ({
                                      ...old,
                                      [role]: {...current, targets: value},
                                    }))
                                  }
                                  placeholder={(config.availableTargets || []).join("\n")}
                                  rows={2}
                                />
                              </FormGroup>
                              <Grid hasGutter>
                                <GridItem sm={7}>
                                  <FormGroup label="Routing strategy">
                                    <FormSelect
                                      value={current.strategy}
                                      onChange={(_e, value) =>
                                        setRoles((old) => ({
                                          ...old,
                                          [role]: {...current, strategy: value},
                                        }))
                                      }
                                    >
                                      <FormSelectOption value="warm" label="Warm / ready first" />
                                      <FormSelectOption value="pin" label="Pin first target" />
                                      <FormSelectOption value="spillover" label="Spillover" />
                                    </FormSelect>
                                  </FormGroup>
                                </GridItem>
                                {current.strategy === "spillover" && (
                                  <GridItem sm={5}>
                                    <FormGroup label="Requests/target">
                                      <TextInput
                                        type="number"
                                        min={1}
                                        max={128}
                                        value={current.spillover}
                                        onChange={(_e, value) =>
                                          setRoles((old) => ({
                                            ...old,
                                            [role]: {...current, spillover: value},
                                          }))
                                        }
                                      />
                                    </FormGroup>
                                  </GridItem>
                                )}
                              </Grid>
                              <Button
                                variant="secondary"
                                onClick={() => saveRole(role)}
                                isLoading={roleBusy === role}
                                isDisabled={
                                  Boolean(roleBusy) || lines(current.targets).length === 0
                                }
                              >
                                Save {label}
                              </Button>
                            </Form>
                          </StackItem>
                        );
                      })}
                      {(config.availableTargets || []).length === 0 && (
                        <Alert variant="info" title="No model targets configured" isInline>
                          Add a remote provider or a local llama-swap model before assigning coding
                          roles.
                        </Alert>
                      )}
                    </Stack>
                  </CardBody>
                </Card>
              </StackItem>
              <StackItem>
                <Card>
                  <CardTitle>llama-swap runtime limits</CardTitle>
                  <CardBody>
                    <Form onSubmit={saveAdvanced}>
                      <FormGroup label="Health check timeout (s)">
                        <TextInput
                          type="number"
                          min={15}
                          max={3600}
                          value={advanced.healthCheckTimeout}
                          onChange={(_e, value) =>
                            setAdvanced((old) => ({...old, healthCheckTimeout: value}))
                          }
                        />
                      </FormGroup>
                      <FormGroup label="Default model idle TTL (s)">
                        <TextInput
                          type="number"
                          min={0}
                          max={604800}
                          value={advanced.globalTTL}
                          onChange={(_e, value) =>
                            setAdvanced((old) => ({...old, globalTTL: value}))
                          }
                        />
                      </FormGroup>
                      <FormGroup label="Model unload grace timeout (s)">
                        <TextInput
                          type="number"
                          min={0}
                          max={3600}
                          value={advanced.unloadTimeout}
                          onChange={(_e, value) =>
                            setAdvanced((old) => ({...old, unloadTimeout: value}))
                          }
                        />
                      </FormGroup>
                      <FormGroup label="Log level">
                        <FormSelect
                          value={advanced.logLevel}
                          onChange={(_e, value) =>
                            setAdvanced((old) => ({...old, logLevel: value}))
                          }
                        >
                          {["debug", "info", "warn", "error"].map((value) => (
                            <FormSelectOption key={value} value={value} label={value} />
                          ))}
                        </FormSelect>
                      </FormGroup>
                      <FormGroup label="Capture buffer (MiB)">
                        <TextInput
                          type="number"
                          min={0}
                          max={1024}
                          value={advanced.captureBuffer}
                          onChange={(_e, value) =>
                            setAdvanced((old) => ({...old, captureBuffer: value}))
                          }
                        />
                      </FormGroup>
                      <FormGroup label="Metrics retained in memory">
                        <TextInput
                          type="number"
                          min={0}
                          max={1000000}
                          value={advanced.metricsMaxInMemory}
                          onChange={(_e, value) =>
                            setAdvanced((old) => ({...old, metricsMaxInMemory: value}))
                          }
                        />
                      </FormGroup>
                      <Button
                        type="submit"
                        variant="secondary"
                        isLoading={advancedBusy}
                        isDisabled={advancedBusy}
                      >
                        Save runtime settings
                      </Button>
                    </Form>
                  </CardBody>
                </Card>
              </StackItem>
            </Stack>
          </GridItem>
        </Grid>
      )}
      <p className="nas-muted">
        Install-time security boundaries—service UIDs, ports, allowed workspace roots, extension
        installation, and systemd sandbox policy—remain declarative NixOS settings. Runtime local
        models, remote/cloud providers, provider policy, coding role routing, and safe llama-swap
        tuning are managed here.
      </p>
      <Modal
        isOpen={Boolean(localDeleteTarget)}
        onClose={localBusy ? undefined : () => setLocalDeleteTarget(null)}
        aria-labelledby="ai-local-model-delete-title"
      >
        <ModalHeader title="Remove local AI model" labelId="ai-local-model-delete-title" />
        <ModalBody>
          Remove <strong>{localDeleteTarget?.id}</strong> from the Cockpit-managed llama-swap
          configuration? The GGUF file itself will not be deleted. Any coding-role target using this
          model will be removed.
        </ModalBody>
        <ModalFooter>
          <Button
            variant="danger"
            onClick={() => localDeleteTarget && deleteLocalModel(localDeleteTarget)}
            isLoading={localBusy}
            isDisabled={localBusy}
          >
            Remove model configuration
          </Button>
          <Button variant="link" onClick={() => setLocalDeleteTarget(null)} isDisabled={localBusy}>
            Cancel
          </Button>
        </ModalFooter>
      </Modal>
      <Modal
        isOpen={Boolean(deleteTarget)}
        onClose={providerBusy ? undefined : () => setDeleteTarget(null)}
        aria-labelledby="ai-provider-delete-title"
      >
        <ModalHeader title="Remove AI provider" labelId="ai-provider-delete-title" />
        <ModalBody>
          Remove <strong>{deleteTarget?.id}</strong>? Any coding-role targets using this provider
          will be removed.
          {deleteTarget?.credentialConfigured && (
            <p className="nas-muted">
              This provider has a KeePass credential. Enter the KeePassXC database password in the
              provider form before confirming so the stored key is removed too.
            </p>
          )}
        </ModalBody>
        <ModalFooter>
          <Button
            variant="danger"
            onClick={() => deleteTarget && deleteProvider(deleteTarget)}
            isLoading={providerBusy}
            isDisabled={providerBusy || (deleteTarget?.credentialConfigured && !keepassPassword)}
          >
            Remove provider
          </Button>
          <Button variant="link" onClick={() => setDeleteTarget(null)} isDisabled={providerBusy}>
            Cancel
          </Button>
        </ModalFooter>
      </Modal>
    </PageSection>
  );
}

function StorageAndFailures({data, onRequestAction}) {
  const replicationBusy = operationBusy(data, "zfs-replicate");
  return (
    <PageSection>
      <Grid hasGutter>
        <GridItem md={6}>
          <Card isFullHeight>
            <CardTitle>ZFS</CardTitle>
            <CardBody>
              <Stack hasGutter>
                <StackItem>
                  <Output ariaLabel="ZFS status">{`${data.zpool?.text || ""}\n${data.zfs?.text || ""}`}</Output>
                </StackItem>
                {data.zfsReplicationInstalled && (
                  <StackItem>
                    <Button
                      isDisabled={replicationBusy}
                      onClick={() => onRequestAction("zfs-replicate", "Replicate ZFS now")}
                    >
                      Replicate ZFS now
                    </Button>
                  </StackItem>
                )}
              </Stack>
            </CardBody>
          </Card>
        </GridItem>
        <GridItem md={6}>
          <Card isFullHeight>
            <CardTitle>Failed units</CardTitle>
            <CardBody>
              <Output ariaLabel="Failed units">
                {data.failedUnits?.length ? data.failedUnits.join("\n") : "No failed units"}
              </Output>
            </CardBody>
          </Card>
        </GridItem>
      </Grid>
    </PageSection>
  );
}

function Links({data}) {
  const visible = new Set(enabledLinkKeys(data));
  return (
    <PageSection>
      <Toolbar className="nas-section-heading">
        <ToolbarContent>
          <ToolbarItem variant="label">
            <Title headingLevel="h2">Applications and tools</Title>
          </ToolbarItem>
          <ToolbarItem align={{default: "alignEnd"}}>
            <Button
              component="a"
              href="docs/index.html"
              target="_blank"
              rel="noopener noreferrer"
              variant="secondary"
            >
              Open help
            </Button>
          </ToolbarItem>
        </ToolbarContent>
      </Toolbar>
      <p className="nas-muted nas-section-heading">
        Open the owning application for settings that belong to that service. The NAS page stays
        focused on host-level status and safe appliance actions.
      </p>
      <div className="nas-link-list">
        {Object.entries(data.links || {})
          .filter(([key, href]) => visible.has(key) && safeInternalPath(href))
          .map(([key, href]) => (
            <Button
              key={key}
              component="a"
              href={href}
              target="_blank"
              rel="noopener noreferrer"
              variant="secondary"
            >
              {LINK_LABELS[key] || key}
            </Button>
          ))}
      </div>
    </PageSection>
  );
}

function Operations({data, onRequestAction}) {
  const active = data.operationState?.active || [];
  return (
    <PageSection>
      <Title headingLevel="h2" className="nas-section-heading">
        Maintenance actions
      </Title>
      {active.length > 0 && (
        <Alert
          variant="info"
          title="Privileged operation in progress"
          isInline
          className="nas-section-heading"
        >
          {active
            .map(
              (item) =>
                `${item.action} (started ${new Date(item.startedAt * 1000).toLocaleString()})`,
            )
            .join(" · ")}
        </Alert>
      )}
      <div className="nas-action-list">
        {visibleOperations(data).map(([id, label]) => (
          <Button
            key={id}
            variant="secondary"
            isDisabled={operationBusy(data, id)}
            onClick={() => onRequestAction(id, label)}
          >
            {label}
          </Button>
        ))}
      </div>
    </PageSection>
  );
}

function Services({data}) {
  return (
    <PageSection>
      <Title headingLevel="h2" className="nas-section-heading">
        System services
      </Title>
      <div className="nas-table-wrap" tabIndex={0} role="region" aria-label="NAS services">
        <table
          className="pf-v6-c-table pf-m-grid-md nas-table"
          role="grid"
          aria-label="NAS services"
        >
          <thead>
            <tr>
              <th>Unit</th>
              <th>Active</th>
              <th>Enabled</th>
            </tr>
          </thead>
          <tbody>
            {(data.services || []).map((item) => (
              <tr key={item.unit}>
                <td data-label="Unit">
                  <code>{item.unit}</code>
                </td>
                <td data-label="Active">
                  <StatusLabel value={item.active}>{item.active || "unknown"}</StatusLabel>
                </td>
                <td data-label="Enabled">
                  <StatusLabel value={item.enabled}>{item.enabled || "unknown"}</StatusLabel>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </PageSection>
  );
}

function Timers({data}) {
  return (
    <PageSection>
      <Title headingLevel="h2" className="nas-section-heading">
        Scheduled maintenance
      </Title>
      <Output ariaLabel="Scheduled maintenance">
        {data.timers?.length ? data.timers.join("\n") : "No NAS timers found"}
      </Output>
    </PageSection>
  );
}

function ActionModal({action, running, error, onClose, onConfirm}) {
  return (
    <Modal
      isOpen={Boolean(action)}
      onClose={running ? undefined : onClose}
      aria-labelledby="nas-action-modal-title"
    >
      <ModalHeader title="Confirm maintenance action" labelId="nas-action-modal-title" />
      <ModalBody>
        Run <strong>{action?.label}</strong>? The NAS will execute the reviewed maintenance action
        and report the result here.
        {error && (
          <Alert variant="danger" title="Operation failed" isInline>
            {error}
          </Alert>
        )}
      </ModalBody>
      <ModalFooter>
        <Button variant="primary" onClick={onConfirm} isLoading={running} isDisabled={running}>
          Run action
        </Button>
        <Button variant="link" onClick={onClose} isDisabled={running}>
          Cancel
        </Button>
      </ModalFooter>
    </Modal>
  );
}

export default function App() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState(null);
  const [busyFeature, setBusyFeature] = useState(null);
  const [action, setAction] = useState(null);
  const [actionRunning, setActionRunning] = useState(false);
  const [actionError, setActionError] = useState("");

  const refresh = useCallback(async ({quiet = false} = {}) => {
    if (!quiet) setLoading(true);
    try {
      setData(await api(["overview"]));
    } catch (error) {
      setNotice({
        variant: "danger",
        title: "Unable to refresh NAS state",
        message: errorText(error),
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);
  useEffect(() => {
    const interval = window.setInterval(() => {
      void refresh({quiet: true});
    }, 5000);
    return () => window.clearInterval(interval);
  }, [refresh]);

  const setup = useMemo(() => setupModel(data || {}), [data]);

  const changeFeature = async (id, mode) => {
    const label = featureMap(data || {})[id]?.label || id;
    setBusyFeature(id);
    setNotice({
      variant: "info",
      title: "Applying service policy",
      message: `Setting ${label} to ${MODE_LABELS[mode] || mode}.`,
    });
    try {
      await api(["feature", id, mode]);
      setNotice({
        variant: "success",
        title: "Service policy applied",
        message: `${label} is now ${MODE_LABELS[mode] || mode}.`,
      });
    } catch (error) {
      setNotice({variant: "danger", title: "Feature policy failed", message: errorText(error)});
    } finally {
      setBusyFeature(null);
      await refresh({quiet: true});
    }
  };

  const requestAction = (id, label) => {
    if (operationBusy(data || {}, id)) {
      setNotice({
        variant: "warning",
        title: "Operation is busy",
        message: `${label} conflicts with another privileged operation.`,
      });
      return;
    }
    setActionError("");
    setAction({id, label});
  };
  const runAction = async () => {
    if (!action) return;
    setActionError("");
    setActionRunning(true);
    try {
      await api(["action", action.id]);
      setNotice({
        variant: "success",
        title: "Operation completed",
        message: `${action.label} completed successfully.`,
      });
      setAction(null);
      await refresh({quiet: true});
    } catch (error) {
      setActionError(errorText(error));
    } finally {
      setActionRunning(false);
    }
  };

  return (
    <Page className="nas-page">
      <PageSection>
        <Toolbar className="nas-page__header">
          <ToolbarContent>
            <ToolbarItem>
              <Title headingLevel="h1">NAS Overview</Title>
              <p className="nas-page__subtitle">
                Storage, access, service policy, maintenance, and recovery status in one place.
              </p>
            </ToolbarItem>
            <ToolbarItem align={{default: "alignEnd"}}>
              <Button
                variant="secondary"
                onClick={() => refresh()}
                isDisabled={loading}
                icon={loading ? <Spinner size="sm" /> : undefined}
              >
                Refresh
              </Button>
            </ToolbarItem>
          </ToolbarContent>
        </Toolbar>
      </PageSection>
      {notice && (
        <PageSection>
          <Notice notice={notice} onClose={() => setNotice(null)} />
        </PageSection>
      )}
      {loading && !data ? (
        <PageSection>
          <Spinner aria-label="Loading NAS state" />
        </PageSection>
      ) : (
        data && (
          <>
            {setup.pending && (
              <FirstStartPanel model={setup} onComplete={refresh} setNotice={setNotice} />
            )}
            {setup.complete && !data.protectedReady && (
              <UnlockPanel model={setup} onComplete={refresh} setNotice={setNotice} />
            )}
            <SummaryCards data={data} />
            {setup.complete && data.protectedReady && (
              <>
                <StorageAndFailures data={data} onRequestAction={requestAction} />
                <Operations data={data} onRequestAction={requestAction} />
                <FeatureGrid data={data} busyFeature={busyFeature} onModeChange={changeFeature} />
                <AIConfiguration data={data} onRefresh={refresh} setNotice={setNotice} />
                <Links data={data} />
                <CapabilityTable data={data} />
                <Services data={data} />
                <Timers data={data} />
                <MemoryTable data={data} />
              </>
            )}
          </>
        )
      )}
      <ActionModal
        action={action}
        running={actionRunning}
        error={actionError}
        onClose={() => {
          setAction(null);
          setActionError("");
        }}
        onConfirm={runAction}
      />
    </Page>
  );
}
