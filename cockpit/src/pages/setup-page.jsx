import React, {useEffect, useState} from "react";
import {
  Alert,
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  Checkbox,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Form,
  FormGroup,
  Stack,
  StackItem,
  TextArea,
  TextInput,
  Title,
} from "@patternfly/react-core";
import {api, apiInput, startFirstRun} from "../api.js";
import {OutputBlock} from "../components/output-block.jsx";
import {pretty} from "../lib/format.js";
import {setupModel} from "../view-model.js";

export function SetupPage({data, mutate, busy}) {
  const model = setupModel(data || {});
  const [password, setPassword] = useState("");
  const [administrator, setAdministrator] = useState({
    username: "",
    name: "",
    email: "",
    password: "",
  });
  const [selectedDevices, setSelectedDevices] = useState([]);
  const [allowDestructive, setAllowDestructive] = useState(false);
  const [confirmPasswordReapply, setConfirmPasswordReapply] = useState(false);
  const [job, setJob] = useState(null);
  const [recoveryNote, setRecoveryNote] = useState("");
  const devices = Array.isArray(model.storage?.devices) ? model.storage.devices : [];

  const submit = async () => {
    const value = await startFirstRun(password, administrator, {
      planDigest: model.planDigest,
      devices: selectedDevices,
      allowDestructiveStorage: allowDestructive,
      confirmPasswordReapply,
    });
    setPassword("");
    setAdministrator({...administrator, password: ""});
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
    <Stack hasGutter>
      <StackItem>
        <Title headingLevel="h2">First start</Title>
      </StackItem>
      <StackItem>
        <Alert
          variant={model.complete ? "success" : model.ready ? "info" : "warning"}
          title={`Setup status: ${model.status}`}
          isInline
        >
          <p>{model.message}</p>
          <DescriptionList isHorizontal>
            <DescriptionListGroup>
              <DescriptionListTerm>Plan</DescriptionListTerm>
              <DescriptionListDescription>
                A new local and Authentik administrator will be created, with {model.serviceCount}{" "}
                V2 service policy overrides
              </DescriptionListDescription>
            </DescriptionListGroup>
            {model.configPath ? (
              <DescriptionListGroup>
                <DescriptionListTerm>Configuration</DescriptionListTerm>
                <DescriptionListDescription>
                  <code>{model.configPath}</code>
                </DescriptionListDescription>
              </DescriptionListGroup>
            ) : null}
          </DescriptionList>
        </Alert>
      </StackItem>
      {!model.complete ? (
        <StackItem>
          <Card>
            <CardHeader>
              <CardTitle>Review and start setup</CardTitle>
            </CardHeader>
            <CardBody>
              <Form>
                <FormGroup
                  label="KeePassXC database password"
                  fieldId="first-start-keepass-password"
                >
                  <TextInput
                    id="first-start-keepass-password"
                    type="password"
                    value={password}
                    onChange={(_e, value) => setPassword(value)}
                  />
                </FormGroup>
                <FormGroup
                  label="Administrator username"
                  fieldId="first-start-administrator-username"
                >
                  <TextInput
                    id="first-start-administrator-username"
                    value={administrator.username}
                    onChange={(_event, value) =>
                      setAdministrator({...administrator, username: value})
                    }
                  />
                </FormGroup>
                <FormGroup label="Administrator name" fieldId="first-start-administrator-name">
                  <TextInput
                    id="first-start-administrator-name"
                    value={administrator.name}
                    onChange={(_event, value) => setAdministrator({...administrator, name: value})}
                  />
                </FormGroup>
                <FormGroup label="Administrator email" fieldId="first-start-administrator-email">
                  <TextInput
                    id="first-start-administrator-email"
                    type="email"
                    value={administrator.email}
                    onChange={(_event, value) => setAdministrator({...administrator, email: value})}
                  />
                </FormGroup>
                <FormGroup
                  label="Administrator password"
                  fieldId="first-start-administrator-password"
                >
                  <TextInput
                    id="first-start-administrator-password"
                    type="password"
                    value={administrator.password}
                    onChange={(_event, value) =>
                      setAdministrator({...administrator, password: value})
                    }
                  />
                </FormGroup>
                {devices.length ? (
                  <FormGroup label="Confirmed storage devices">
                    <Stack hasGutter>
                      {devices.map((device) => (
                        <Checkbox
                          id={`first-start-device-${device}`}
                          key={device}
                          label={<code>{device}</code>}
                          isChecked={selectedDevices.includes(device)}
                          onChange={(_event, checked) =>
                            setSelectedDevices(
                              checked
                                ? [...selectedDevices, device]
                                : selectedDevices.filter((value) => value !== device),
                            )
                          }
                        />
                      ))}
                    </Stack>
                  </FormGroup>
                ) : null}
                {model.destructiveRequired ? (
                  <Checkbox
                    id="first-start-destructive"
                    label="I reviewed the exact device list and permit destructive pool creation."
                    isChecked={allowDestructive}
                    onChange={(_event, checked) => setAllowDestructive(checked)}
                  />
                ) : null}
                <Checkbox
                  id="first-start-password-reapply"
                  label="Permit reapplying password mutations if resuming an incomplete account stage."
                  isChecked={confirmPasswordReapply}
                  onChange={(_event, checked) => setConfirmPasswordReapply(checked)}
                />
                <Button
                  onClick={submit}
                  isDisabled={
                    busy ||
                    !model.ready ||
                    !password ||
                    !administrator.username ||
                    !administrator.name ||
                    !administrator.email ||
                    !administrator.password ||
                    (model.destructiveRequired && !allowDestructive)
                  }
                >
                  Start
                </Button>
              </Form>
            </CardBody>
          </Card>
        </StackItem>
      ) : null}
      {job ? (
        <StackItem>
          <Card>
            <CardHeader>
              <CardTitle>First-start job</CardTitle>
            </CardHeader>
            <CardBody>
              <OutputBlock>{pretty(job)}</OutputBlock>
            </CardBody>
          </Card>
        </StackItem>
      ) : null}
      {model.journal?.status === "manual-recovery-required" ? (
        <StackItem>
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
        </StackItem>
      ) : null}
    </Stack>
  );
}
