import React, {useState} from "react";
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  ModalVariant,
  Title,
} from "@patternfly/react-core";
import {api} from "../api.js";
import {OutputBlock} from "../components/output-block.jsx";
import {pretty} from "../lib/format.js";
import {visibleOperations} from "../view-model.js";

export function OperationsPage({data, mutate, busy}) {
  const operations = visibleOperations(data || {});
  const [pending, setPending] = useState(null);
  const [lastResult, setLastResult] = useState(null);
  const run = async (id) => {
    try {
      const result = await mutate(() => api(["action", id]));
      setPending(null);
      setLastResult(result);
    } catch (_reason) {
      // The shared mutation hook keeps the failed action visible and reports its error.
    }
  };
  return (
    <>
      <Title headingLevel="h2">Operations</Title>
      <div className="nas-actions nas-actions--wrap">
        {operations.map(([id, label]) => (
          <Button
            key={id}
            variant="secondary"
            onClick={() => setPending({id, label})}
            isDisabled={busy}
          >
            {label}
          </Button>
        ))}
      </div>
      {pending ? (
        <Modal
          isOpen
          variant={ModalVariant.small}
          aria-label="Confirm maintenance action"
          onClose={() => setPending(null)}
        >
          <ModalHeader title="Confirm maintenance action" titleIconVariant="warning" />
          <ModalBody>
            <p>
              Run <strong>{pending.label}</strong>? This action can change appliance state.
            </p>
          </ModalBody>
          <ModalFooter>
            <Button variant="danger" onClick={() => run(pending.id)} isDisabled={busy}>
              Confirm
            </Button>
            <Button variant="link" onClick={() => setPending(null)} isDisabled={busy}>
              Cancel
            </Button>
          </ModalFooter>
        </Modal>
      ) : null}
      <Card>
        <CardHeader>
          <CardTitle>Operation coordinator</CardTitle>
        </CardHeader>
        <CardBody>
          <OutputBlock>{pretty(data?.operations || {})}</OutputBlock>
        </CardBody>
      </Card>
      {lastResult ? (
        <Card>
          <CardBody>
            <OutputBlock>{pretty(lastResult)}</OutputBlock>
          </CardBody>
        </Card>
      ) : null}
    </>
  );
}
