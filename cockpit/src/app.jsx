import React, {useCallback, useEffect, useMemo, useState} from "react";
import {
  Alert,
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  Form,
  FormGroup,
  Label,
  Spinner,
  TextArea,
  TextInput,
  Title,
} from "@patternfly/react-core";
import {
  activateSecrets,
  api,
  apiInput,
  managedServicesDocument,
  replaceManagedServicesDocument,
  replaceManagedServicesJsonDocument,
  setManagedServiceMode,
  startFirstRun,
} from "./api.js";
import {SchemaEditor} from "./schema-editor.jsx";
import {
  MODE_LABELS,
  managedApplicationLinks,
  managedServiceOperationsBusy,
  managedServiceRows,
  managedServiceRuntimeText,
  managedServiceUnitState,
  mib,
  revisionModel,
  setupModel,
  staticLinks,
  visibleOperations,
} from "./view-model.js";

const PAGES = [
  ["overview", "Overview"],
  ["services", "Managed services"],
  ["applications", "Applications"],
  ["operations", "Operations"],
  ["ai", "AI configuration"],
  ["source", "Source & updates"],
  ["setup", "First start"],
];

function message(error) {
  if (error instanceof Error) return error.message;
  return String(error || "Unknown error");
}

function pretty(value) {
  return JSON.stringify(value, null, 2);
}

function useOverview() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      setData(await api(["overview"]));
      setError("");
    } catch (reason) {
      setError(message(reason));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return {data, loading, error, refresh, setData};
}

function Status({ok, children}) {
  return <Label color={ok ? "green" : "orange"}>{children}</Label>;
}

function LinkCard({entry}) {
  return (
    <Card isCompact>
      <CardHeader>
        <CardTitle>{entry.label}</CardTitle>
      </CardHeader>
      <CardBody>
        {entry.description ? <p>{entry.description}</p> : null}
        <Button component="a" href={entry.url} variant="link" isInline>
          Open
        </Button>
      </CardBody>
    </Card>
  );
}

function OverviewPage({data, refresh, busy}) {
  const setup = setupModel(data || {});
  const services = managedServiceRows(data || {});
  const running = services.filter((service) => service.running).length;
  const zfsHealthy = data?.zfs?.healthy === true;
  return (
    <div className="nas-grid nas-grid--overview">
      <Card>
        <CardHeader>
          <CardTitle>Appliance</CardTitle>
        </CardHeader>
        <CardBody>
          <p>
            <strong>{data?.host || "NAS"}</strong>
          </p>
          <p>
            Protected services:{" "}
            <Status ok={data?.protectedReady === true}>
              {data?.protectedReady ? "ready" : "locked"}
            </Status>
          </p>
          <p>
            First start: <Status ok={setup.complete}>{setup.status}</Status>
          </p>
        </CardBody>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Managed Services V2</CardTitle>
        </CardHeader>
        <CardBody>
          <p>{services.length} services in the current authority.</p>
          <p>{running} native owner units currently active.</p>
          <Button variant="secondary" onClick={refresh} isDisabled={busy}>
            Refresh
          </Button>
        </CardBody>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>ZFS</CardTitle>
        </CardHeader>
        <CardBody>
          <p>
            <Status ok={zfsHealthy}>{zfsHealthy ? "healthy" : "attention required"}</Status>
          </p>
          <pre className="nas-pre">{data?.zfs?.summary || "Unavailable"}</pre>
          <pre className="nas-pre">{data?.zfs?.dataset || ""}</pre>
        </CardBody>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Failures</CardTitle>
        </CardHeader>
        <CardBody>
          {Array.isArray(data?.failedUnits) && data.failedUnits.length ? (
            <pre className="nas-pre">{data.failedUnits.join("\n")}</pre>
          ) : (
            <p>No failed units reported.</p>
          )}
        </CardBody>
      </Card>
    </div>
  );
}

function ServiceCard({service, onMode, disabled}) {
  const modes = Array.isArray(service.allowedModes) ? service.allowedModes : ["off", "always"];
  return (
    <Card isCompact>
      <CardHeader>
        <CardTitle>{service.label || service.id}</CardTitle>
      </CardHeader>
      <CardBody>
        <div className="nas-card-row">
          <Status ok={service.healthy === true || service.effectiveMode === "on-demand"}>
            {managedServiceUnitState(service)}
          </Status>
          <Label>{MODE_LABELS[service.requestedMode] || service.requestedMode || "unknown"}</Label>
        </div>
        <p>{service.description || service.id}</p>
        <p className="nas-muted">{managedServiceRuntimeText(service)}</p>
        {service.managed === false ? (
          <p className="nas-muted">
            This entry is visible to V2 for dependencies/routes; its native lifecycle is
            platform-owned.
          </p>
        ) : (
          <label className="nas-field">
            <span>Lifecycle mode</span>
            <select
              value={service.requestedMode || "off"}
              disabled={disabled}
              onChange={(event) => onMode(service.id, event.target.value)}
            >
              {modes.map((mode) => (
                <option key={mode} value={mode}>
                  {MODE_LABELS[mode] || mode}
                </option>
              ))}
            </select>
          </label>
        )}
        {Array.isArray(service.units) && service.units.length ? (
          <div className="nas-unit-list">
            {service.units.map((unit) => (
              <div key={unit.unit}>
                <code>{unit.unit}</code> ·{" "}
                {unit.activeState || (unit.active ? "active" : "inactive")} ·{" "}
                {mib(unit.memoryBytes)} MiB
              </div>
            ))}
          </div>
        ) : null}
      </CardBody>
    </Card>
  );
}

function ServicesPage({data, mutate, busy}) {
  const services = managedServiceRows(data || {});
  const serviceBusy = managedServiceOperationsBusy(data || {}) || busy;
  const [document, setDocument] = useState(null);
  const [formValue, setFormValue] = useState(null);
  const [yaml, setYaml] = useState("");
  const [editorMode, setEditorMode] = useState("form");
  const [editorError, setEditorError] = useState("");
  const [saving, setSaving] = useState(false);

  const loadDocument = async () => {
    try {
      const value = await managedServicesDocument();
      setDocument(value);
      setFormValue(value.document || null);
      setYaml(value.yaml || "");
      setEditorMode("form");
      setEditorError("");
    } catch (reason) {
      setEditorError(message(reason));
    }
  };

  const saveFormDocument = async () => {
    setSaving(true);
    try {
      await mutate(() => replaceManagedServicesJsonDocument(formValue));
      setEditorError("");
      await loadDocument();
    } catch (reason) {
      setEditorError(message(reason));
    } finally {
      setSaving(false);
    }
  };

  const saveYamlDocument = async () => {
    setSaving(true);
    try {
      await mutate(() => replaceManagedServicesDocument(yaml));
      setEditorError("");
      await loadDocument();
    } catch (reason) {
      setEditorError(message(reason));
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      <div className="nas-section-header">
        <div>
          <Title headingLevel="h2">Managed Services V2</Title>
          <p>/var/lib/nas-control/services.yaml is the sole mutable lifecycle authority.</p>
        </div>
        <Button variant="secondary" onClick={loadDocument}>
          Edit services
        </Button>
      </div>
      <div className="nas-grid">
        {services.map((service) => (
          <ServiceCard
            key={service.id}
            service={service}
            disabled={serviceBusy}
            onMode={(serviceId, mode) => mutate(() => setManagedServiceMode(serviceId, mode))}
          />
        ))}
      </div>
      {document ? (
        <Card className="nas-editor-card">
          <CardHeader>
            <CardTitle>Schema-driven desired state</CardTitle>
          </CardHeader>
          <CardBody>
            <p className="nas-muted">
              The form below is generated from the same JSON Schema used by the V2 compiler. Raw
              YAML remains available for advanced edits.
            </p>
            {editorError ? <Alert variant="danger" isInline title={editorError} /> : null}
            <div className="nas-actions">
              <Button
                variant={editorMode === "form" ? "primary" : "secondary"}
                onClick={() => setEditorMode("form")}
              >
                Schema form
              </Button>
              <Button
                variant={editorMode === "yaml" ? "primary" : "secondary"}
                onClick={() => setEditorMode("yaml")}
              >
                Advanced YAML
              </Button>
            </div>
            {editorMode === "form" && formValue ? (
              <SchemaEditor schema={document.schema} value={formValue} onChange={setFormValue} />
            ) : (
              <TextArea
                value={yaml}
                onChange={(_event, value) => setYaml(value)}
                rows={24}
                resizeOrientation="vertical"
              />
            )}
            <div className="nas-actions">
              <Button
                onClick={editorMode === "form" ? saveFormDocument : saveYamlDocument}
                isLoading={saving}
                isDisabled={saving || (editorMode === "form" && !formValue)}
              >
                Validate, save, and reconcile
              </Button>
              <Button variant="link" onClick={() => setDocument(null)}>
                Close
              </Button>
            </div>
          </CardBody>
        </Card>
      ) : null}
    </>
  );
}

function ApplicationsPage({data}) {
  const managed = managedApplicationLinks(data || {});
  const staticEntries = staticLinks(data || {});
  const grouped = useMemo(() => {
    const result = new Map();
    for (const entry of managed) {
      if (!result.has(entry.category)) result.set(entry.category, []);
      result.get(entry.category).push(entry);
    }
    return result;
  }, [managed]);
  return (
    <>
      <Title headingLevel="h2">Applications</Title>
      <p>
        Application links are projected from Managed Services V2 route metadata; Caddy still
        enforces authorization on every request.
      </p>
      {[...grouped.entries()].map(([category, entries]) => (
        <section key={category} className="nas-section">
          <Title headingLevel="h3">{category}</Title>
          <div className="nas-grid">
            {entries.map((entry) => (
              <LinkCard key={entry.id} entry={entry} />
            ))}
          </div>
        </section>
      ))}
      <section className="nas-section">
        <Title headingLevel="h3">Platform tools</Title>
        <div className="nas-grid">
          {staticEntries.map((entry) => (
            <LinkCard key={entry.key} entry={entry} />
          ))}
        </div>
      </section>
    </>
  );
}

function OperationsPage({data, mutate, busy}) {
  const operations = visibleOperations(data || {});
  const confirmationRequired = new Set([
    "snapshot",
    "zfs-scrub",
    "backup",
    "replicate",
    "update-sync",
    "update-apply",
    "protected-restart",
  ]);
  const [pending, setPending] = useState(null);
  const [lastResult, setLastResult] = useState(null);
  const run = async (id) => {
    const result = await mutate(() => api(["action", id]));
    setPending(null);
    setLastResult(result);
  };
  return (
    <>
      <Title headingLevel="h2">Operations</Title>
      <div className="nas-actions nas-actions--wrap">
        {operations.map(([id, label]) => (
          <Button
            key={id}
            variant="secondary"
            onClick={() => (confirmationRequired.has(id) ? setPending({id, label}) : run(id))}
            isDisabled={busy}
          >
            {label}
          </Button>
        ))}
      </div>
      {pending ? (
        <Card>
          <CardHeader>
            <CardTitle>Confirm maintenance action</CardTitle>
          </CardHeader>
          <CardBody>
            <p>
              Run <strong>{pending.label}</strong>? This action can change appliance state.
            </p>
            <div className="nas-actions">
              <Button variant="danger" onClick={() => run(pending.id)} isDisabled={busy}>
                Confirm
              </Button>
              <Button variant="link" onClick={() => setPending(null)} isDisabled={busy}>
                Cancel
              </Button>
            </div>
          </CardBody>
        </Card>
      ) : null}
      <Card>
        <CardHeader>
          <CardTitle>Operation coordinator</CardTitle>
        </CardHeader>
        <CardBody>
          <pre className="nas-pre">{pretty(data?.operations || {})}</pre>
        </CardBody>
      </Card>
      {lastResult ? (
        <Card>
          <CardBody>
            <pre className="nas-pre">{pretty(lastResult)}</pre>
          </CardBody>
        </Card>
      ) : null}
    </>
  );
}

function AiPage({data, mutate, busy}) {
  const config = data?.aiConfig && typeof data.aiConfig === "object" ? data.aiConfig : {};
  const [provider, setProvider] = useState({
    id: "",
    url: "",
    models: "",
    apiKey: "",
    keepassPassword: "",
  });
  const [providerDelete, setProviderDelete] = useState({id: "", keepassPassword: ""});
  const [local, setLocal] = useState({
    id: "",
    path: "",
    context: "4096",
    ttl: "-1",
    tools: false,
    extraArgs: "",
  });
  const [role, setRole] = useState({
    role: "default",
    targets: "",
    strategy: "fallback",
    spillover: "1",
  });
  const [advanced, setAdvanced] = useState("{}");
  const [result, setResult] = useState(null);

  const submit = async (call) => setResult(await mutate(call));
  return (
    <>
      <Title headingLevel="h2">AI configuration</Title>
      <div className="nas-grid">
        <Card>
          <CardHeader>
            <CardTitle>Current llama-swap configuration</CardTitle>
          </CardHeader>
          <CardBody>
            <pre className="nas-pre">{pretty(config)}</pre>
          </CardBody>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Set remote provider</CardTitle>
          </CardHeader>
          <CardBody>
            <Form>
              <FormGroup label="Provider ID">
                <TextInput
                  value={provider.id}
                  onChange={(_e, value) => setProvider({...provider, id: value})}
                />
              </FormGroup>
              <FormGroup label="OpenAI-compatible URL">
                <TextInput
                  value={provider.url}
                  onChange={(_e, value) => setProvider({...provider, url: value})}
                />
              </FormGroup>
              <FormGroup label="Models (comma-separated)">
                <TextInput
                  value={provider.models}
                  onChange={(_e, value) => setProvider({...provider, models: value})}
                />
              </FormGroup>
              <FormGroup label="API key">
                <TextInput
                  type="password"
                  value={provider.apiKey}
                  onChange={(_e, value) => setProvider({...provider, apiKey: value})}
                />
              </FormGroup>
              <FormGroup label="KeePassXC password">
                <TextInput
                  type="password"
                  value={provider.keepassPassword}
                  onChange={(_e, value) => setProvider({...provider, keepassPassword: value})}
                />
              </FormGroup>
              <Button
                isDisabled={busy}
                onClick={() =>
                  submit(() =>
                    apiInput(["ai-provider-set"], {
                      ...provider,
                      models: provider.models
                        .split(",")
                        .map((v) => v.trim())
                        .filter(Boolean),
                    }),
                  )
                }
              >
                Save provider
              </Button>
            </Form>
          </CardBody>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Delete remote provider</CardTitle>
          </CardHeader>
          <CardBody>
            <Form>
              <FormGroup label="Provider ID">
                <TextInput
                  value={providerDelete.id}
                  onChange={(_e, value) => setProviderDelete({...providerDelete, id: value})}
                />
              </FormGroup>
              <FormGroup label="KeePassXC password">
                <TextInput
                  type="password"
                  value={providerDelete.keepassPassword}
                  onChange={(_e, value) =>
                    setProviderDelete({...providerDelete, keepassPassword: value})
                  }
                />
              </FormGroup>
              <Button
                variant="danger"
                isDisabled={busy}
                onClick={() => submit(() => apiInput(["ai-provider-delete"], providerDelete))}
              >
                Delete provider
              </Button>
            </Form>
          </CardBody>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Local model</CardTitle>
          </CardHeader>
          <CardBody>
            <Form>
              <FormGroup label="Model ID">
                <TextInput
                  value={local.id}
                  onChange={(_e, value) => setLocal({...local, id: value})}
                />
              </FormGroup>
              <FormGroup label="GGUF path">
                <TextInput
                  value={local.path}
                  onChange={(_e, value) => setLocal({...local, path: value})}
                />
              </FormGroup>
              <FormGroup label="Context">
                <TextInput
                  value={local.context}
                  onChange={(_e, value) => setLocal({...local, context: value})}
                />
              </FormGroup>
              <FormGroup label="TTL">
                <TextInput
                  value={local.ttl}
                  onChange={(_e, value) => setLocal({...local, ttl: value})}
                />
              </FormGroup>
              <FormGroup label="Extra args (one per line)">
                <TextArea
                  rows={4}
                  value={local.extraArgs}
                  onChange={(_e, value) => setLocal({...local, extraArgs: value})}
                />
              </FormGroup>
              <label>
                <input
                  type="checkbox"
                  checked={local.tools}
                  onChange={(event) => setLocal({...local, tools: event.target.checked})}
                />{" "}
                Tool-capable model
              </label>
              <div className="nas-actions">
                <Button
                  isDisabled={busy}
                  onClick={() =>
                    submit(() =>
                      apiInput(["ai-local-model-set"], {
                        id: local.id,
                        path: local.path,
                        context: Number(local.context),
                        ttl: Number(local.ttl),
                        tools: local.tools,
                        extraArgs: local.extraArgs
                          .split("\n")
                          .map((v) => v.trim())
                          .filter(Boolean),
                      }),
                    )
                  }
                >
                  Save local model
                </Button>
                <Button
                  variant="danger"
                  isDisabled={busy}
                  onClick={() => submit(() => apiInput(["ai-local-model-delete"], {id: local.id}))}
                >
                  Delete local model
                </Button>
              </div>
            </Form>
          </CardBody>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Model role</CardTitle>
          </CardHeader>
          <CardBody>
            <Form>
              <FormGroup label="Role">
                <TextInput
                  value={role.role}
                  onChange={(_e, value) => setRole({...role, role: value})}
                />
              </FormGroup>
              <FormGroup label="Targets (comma-separated)">
                <TextInput
                  value={role.targets}
                  onChange={(_e, value) => setRole({...role, targets: value})}
                />
              </FormGroup>
              <FormGroup label="Strategy">
                <select
                  value={role.strategy}
                  onChange={(event) => setRole({...role, strategy: event.target.value})}
                >
                  <option value="fallback">fallback</option>
                  <option value="round-robin">round-robin</option>
                  <option value="least-busy">least-busy</option>
                </select>
              </FormGroup>
              <FormGroup label="Spillover">
                <TextInput
                  value={role.spillover}
                  onChange={(_e, value) => setRole({...role, spillover: value})}
                />
              </FormGroup>
              <Button
                isDisabled={busy}
                onClick={() =>
                  submit(() =>
                    apiInput(["ai-role-set"], {
                      role: role.role,
                      targets: role.targets
                        .split(",")
                        .map((v) => v.trim())
                        .filter(Boolean),
                      strategy: role.strategy,
                      spillover: Number(role.spillover),
                    }),
                  )
                }
              >
                Save role
              </Button>
            </Form>
          </CardBody>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Advanced AI settings</CardTitle>
          </CardHeader>
          <CardBody>
            <p>Submit only supported llama-swap advanced keys.</p>
            <TextArea rows={10} value={advanced} onChange={(_e, value) => setAdvanced(value)} />
            <Button
              isDisabled={busy}
              onClick={() => submit(() => apiInput(["ai-advanced-set"], JSON.parse(advanced)))}
            >
              Apply advanced settings
            </Button>
          </CardBody>
        </Card>
      </div>
      {result ? (
        <Card>
          <CardHeader>
            <CardTitle>Last AI mutation</CardTitle>
          </CardHeader>
          <CardBody>
            <pre className="nas-pre">{pretty(result)}</pre>
          </CardBody>
        </Card>
      ) : null}
    </>
  );
}

function SourcePage({data, mutate, busy}) {
  const revision = revisionModel(data?.update || {});
  const [result, setResult] = useState(null);
  const run = async (operation) =>
    setResult(await mutate(() => apiInput(["source-control"], {operation})));
  return (
    <>
      <Title headingLevel="h2">Source & updates</Title>
      <Card>
        <CardBody>
          {revision.kind === "error" ? (
            <Alert variant="danger" isInline title={revision.error} />
          ) : (
            <dl className="nas-details">
              <dt>Revision</dt>
              <dd>{revision.revision}</dd>
              <dt>Branch</dt>
              <dd>{revision.branch}</dd>
              <dt>Upstream</dt>
              <dd>{revision.upstream}</dd>
              <dt>State</dt>
              <dd>
                {revision.divergence}; checkout {revision.checkout}
              </dd>
            </dl>
          )}
          <div className="nas-actions nas-actions--wrap">
            {["status", "diff", "log", "pull", "rebuild", "pull-rebuild"].map((operation) => (
              <Button
                key={operation}
                variant="secondary"
                isDisabled={busy}
                onClick={() => run(operation)}
              >
                {operation}
              </Button>
            ))}
          </div>
        </CardBody>
      </Card>
      {result ? (
        <Card>
          <CardBody>
            <pre className="nas-pre">{pretty(result)}</pre>
          </CardBody>
        </Card>
      ) : null}
    </>
  );
}

function SetupPage({data, mutate, busy}) {
  const model = setupModel(data || {});
  const [password, setPassword] = useState("");
  const [selectedDevices, setSelectedDevices] = useState([]);
  const [allowDestructive, setAllowDestructive] = useState(false);
  const [confirmPasswordReapply, setConfirmPasswordReapply] = useState(false);
  const [job, setJob] = useState(null);
  const [recoveryNote, setRecoveryNote] = useState("");
  const devices = Array.isArray(model.storage?.devices) ? model.storage.devices : [];

  const submit = async () => {
    const value = await startFirstRun(password, {
      planDigest: model.planDigest,
      devices: selectedDevices,
      allowDestructiveStorage: allowDestructive,
      confirmPasswordReapply,
    });
    setPassword("");
    setJob(value);
  };

  useEffect(() => {
    if (!job?.jobId || ["complete", "failed"].includes(job.status)) return undefined;
    const timer = window.setInterval(async () => {
      try {
        const value = await api(["first-start-job-status", job.jobId]);
        setJob(value);
      } catch (_reason) {
        // Keep the last visible job state and retry on the next interval.
      }
    }, 1500);
    return () => window.clearInterval(timer);
  }, [job]);

  return (
    <>
      <Title headingLevel="h2">First start</Title>
      <Card>
        <CardBody>
          <p>
            <Status ok={model.complete}>{model.status}</Status>
          </p>
          <p>{model.message}</p>
          <p>
            {model.accountCount} account definitions · {model.serviceCount} V2 service policy
            overrides
          </p>
          {model.configPath ? (
            <p>
              <code>{model.configPath}</code>
            </p>
          ) : null}
        </CardBody>
      </Card>
      {!model.complete ? (
        <Card>
          <CardHeader>
            <CardTitle>Run first start</CardTitle>
          </CardHeader>
          <CardBody>
            <Form>
              <FormGroup label="KeePassXC database password">
                <TextInput
                  type="password"
                  value={password}
                  onChange={(_e, value) => setPassword(value)}
                />
              </FormGroup>
              {devices.length ? (
                <FormGroup label="Confirmed storage devices">
                  {devices.map((device) => (
                    <label key={device} className="nas-checkbox">
                      <input
                        type="checkbox"
                        checked={selectedDevices.includes(device)}
                        onChange={(event) =>
                          setSelectedDevices(
                            event.target.checked
                              ? [...selectedDevices, device]
                              : selectedDevices.filter((value) => value !== device),
                          )
                        }
                      />{" "}
                      <code>{device}</code>
                    </label>
                  ))}
                </FormGroup>
              ) : null}
              {model.destructiveRequired ? (
                <label className="nas-checkbox">
                  <input
                    id="first-start-destructive"
                    type="checkbox"
                    checked={allowDestructive}
                    onChange={(event) => setAllowDestructive(event.target.checked)}
                  />{" "}
                  I reviewed the exact device list and permit destructive pool creation.
                </label>
              ) : null}
              <label className="nas-checkbox">
                <input
                  type="checkbox"
                  checked={confirmPasswordReapply}
                  onChange={(event) => setConfirmPasswordReapply(event.target.checked)}
                />{" "}
                Permit reapplying password mutations if resuming an incomplete account stage.
              </label>
              <Button
                onClick={submit}
                isDisabled={
                  busy ||
                  !model.ready ||
                  !password ||
                  (model.destructiveRequired && !allowDestructive)
                }
              >
                Start
              </Button>
            </Form>
          </CardBody>
        </Card>
      ) : null}
      {job ? (
        <Card>
          <CardHeader>
            <CardTitle>First-start job</CardTitle>
          </CardHeader>
          <CardBody>
            <pre className="nas-pre">{pretty(job)}</pre>
          </CardBody>
        </Card>
      ) : null}
      {model.journal?.status === "manual-recovery-required" ? (
        <Card>
          <CardHeader>
            <CardTitle>Manual recovery acknowledgement</CardTitle>
          </CardHeader>
          <CardBody>
            <TextArea
              rows={4}
              value={recoveryNote}
              onChange={(_e, value) => setRecoveryNote(value)}
            />
            <Button
              isDisabled={busy || !recoveryNote.trim()}
              onClick={() =>
                mutate(() => apiInput(["first-start-reconcile"], {note: recoveryNote}))
              }
            >
              Acknowledge repair
            </Button>
          </CardBody>
        </Card>
      ) : null}
    </>
  );
}

export default function App() {
  const {data, loading, error, refresh} = useOverview();
  const [page, setPage] = useState("overview");
  const [busy, setBusy] = useState(false);
  const [mutationError, setMutationError] = useState("");
  const [notice, setNotice] = useState("");
  const [unlockPassword, setUnlockPassword] = useState("");

  const mutate = useCallback(
    async (operation) => {
      setBusy(true);
      setMutationError("");
      setNotice("");
      try {
        const result = await operation();
        setNotice("Operation completed.");
        await refresh();
        return result;
      } catch (reason) {
        setMutationError(message(reason));
        throw reason;
      } finally {
        setBusy(false);
      }
    },
    [refresh],
  );

  const unlock = async () => {
    setBusy(true);
    setMutationError("");
    try {
      await activateSecrets(unlockPassword);
      setUnlockPassword("");
      setNotice("Runtime secrets activated.");
      await refresh();
    } catch (reason) {
      setMutationError(message(reason));
    } finally {
      setBusy(false);
    }
  };

  let content = null;
  if (loading && !data) content = <Spinner size="xl" />;
  else if (page === "overview")
    content = <OverviewPage data={data} refresh={refresh} busy={busy} />;
  else if (page === "services") content = <ServicesPage data={data} mutate={mutate} busy={busy} />;
  else if (page === "applications") content = <ApplicationsPage data={data} />;
  else if (page === "operations")
    content = <OperationsPage data={data} mutate={mutate} busy={busy} />;
  else if (page === "ai") content = <AiPage data={data} mutate={mutate} busy={busy} />;
  else if (page === "source") content = <SourcePage data={data} mutate={mutate} busy={busy} />;
  else if (page === "setup") content = <SetupPage data={data} mutate={mutate} busy={busy} />;

  return (
    <div className="nas-shell">
      <header className="nas-header">
        <div>
          <Title headingLevel="h1">NixOS NAS</Title>
          <span className="nas-muted">Managed Services V2</span>
        </div>
        <Button variant="secondary" onClick={refresh} isDisabled={busy}>
          Refresh
        </Button>
      </header>
      <div className="nas-layout">
        <nav className="nas-nav" aria-label="NAS sections">
          {PAGES.map(([id, label]) => (
            <button
              key={id}
              type="button"
              className={page === id ? "nas-nav-item nas-nav-item--active" : "nas-nav-item"}
              onClick={() => setPage(id)}
            >
              {label}
            </button>
          ))}
        </nav>
        <main className="nas-main">
          {error ? (
            <Alert variant="danger" isInline title="Unable to load appliance status">
              {error}
            </Alert>
          ) : null}
          {mutationError ? (
            <Alert variant="danger" isInline title="Operation failed">
              {mutationError}
            </Alert>
          ) : null}
          {notice ? <Alert variant="success" isInline title={notice} /> : null}
          {data && data.protectedReady === false ? (
            <Card>
              <CardHeader>
                <CardTitle>Protected services are locked</CardTitle>
              </CardHeader>
              <CardBody>
                <Form>
                  <FormGroup label="KeePassXC database password">
                    <TextInput
                      type="password"
                      value={unlockPassword}
                      onChange={(_e, value) => setUnlockPassword(value)}
                    />
                  </FormGroup>
                  <Button onClick={unlock} isDisabled={busy || !unlockPassword}>
                    Activate secrets
                  </Button>
                </Form>
              </CardBody>
            </Card>
          ) : null}
          {content}
        </main>
      </div>
    </div>
  );
}
