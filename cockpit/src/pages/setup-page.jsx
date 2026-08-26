import React, {useState} from "react";
import {
  Alert,
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Stack,
  StackItem,
  TextArea,
  Title,
} from "@patternfly/react-core";
import {apiInput} from "../api.js";
import {setupModel} from "../view-model.js";

export function SetupPage({data, mutate, busy}) {
  const model = setupModel(data || {});
  const [recoveryNote, setRecoveryNote] = useState("");

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
                {model.complete
                  ? "The permanent appliance trust domain is established."
                  : `The standalone setup flow will create the permanent administrator and apply ${model.serviceCount} V2 service policy overrides.`}
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
              <CardTitle>Standalone first-run setup</CardTitle>
            </CardHeader>
            <CardBody>
              <p>
                First-run passwords and destructive-storage confirmations are accepted only by the
                dedicated authenticated setup service. Cockpit does not collect or persist those
                credentials.
              </p>
              <Button component="a" href="/setup/" isDisabled={busy}>
                Open first-run setup
              </Button>
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
