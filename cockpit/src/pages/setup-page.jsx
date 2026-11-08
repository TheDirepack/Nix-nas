import React, {useState} from "react";
import {Button, Card, CardBody, CardTitle, Form, TextInput, Title} from "@patternfly/react-core";
import {apiInput} from "../api.js";
import {setupModel} from "../view-model.js";

export function SetupPage({data, mutate, busy}) {
  const model = setupModel(data || {});
  const [note, setNote] = useState("");
  const reconcile = async (event) => {
    event.preventDefault();
    try {
      await mutate(() => apiInput(["first-start-reconcile"], {note}));
      setNote("");
    } catch (_error) {
      // The shared mutation hook displays the CLI error.
    }
  };
  return (
    <Card>
      <CardBody>
        <Title headingLevel="h2">First start</Title>
        <CardTitle>{model.status}</CardTitle>
        <p>{model.message}</p>
        {model.journal?.status === "manual-recovery-required" ? (
          <Form onSubmit={reconcile}>
            <TextInput
              aria-label="Recovery note"
              value={note}
              onChange={(_event, value) => setNote(value)}
            />
            <Button type="submit" isDisabled={busy}>
              Acknowledge completed recovery
            </Button>
          </Form>
        ) : null}
        {!model.complete ? (
          <Button component="a" href="/setup/">
            Open setup wizard
          </Button>
        ) : null}
      </CardBody>
    </Card>
  );
}
