import React, {useState} from "react";
import {
  Alert,
  Button,
  Card,
  CardBody,
  CardTitle,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Spinner,
  Title,
} from "@patternfly/react-core";
import {apiInput} from "../api.js";
import {OutputBlock} from "../components/output-block.jsx";
import {pretty} from "../lib/format.js";
import {revisionModel} from "../view-model.js";

const READ_ONLY = ["status", "diff", "log"];
const UPDATE_OPS = [
  {operation: "preview", label: "Validate candidate", description: "Build without activation via nas-update"},
  {operation: "sync", label: "Fetch approved update", description: "Fast-forward to upstream via nas-update --sync"},
  {operation: "apply", label: "Apply validated candidate", description: "Test, health-check, and switch via nas-update --apply"},
];

export function SourcePage({data, mutate, busy}) {
  const revision = revisionModel(data?.update || {});
  const update = data?.update || {};
  const manualRecovery = update.manualRecovery;
  const operations = data?.operations || {};
  const applianceBusy = Array.isArray(operations.busyClasses)
    ? operations.busyClasses.includes("appliance") || operations.busyClasses.includes("update")
    : false;
  const [result, setResult] = useState(null);
  const runSource = async (operation) =>
    setResult(await mutate(() => apiInput(["source-control"], {operation})));
  const runUpdate = async (operation) =>
    setResult(await mutate(() => apiInput(["update-control"], {operation})));
  return (
    <>
      <Title headingLevel="h2">Source & updates</Title>
      <Card>
        <CardBody>
          {revision.kind === "error" ? (
            <Alert variant="danger" isInline title={revision.error} />
          ) : (
            <DescriptionList isHorizontal>
              <DescriptionListGroup>
                <DescriptionListTerm>Revision</DescriptionListTerm>
                <DescriptionListDescription>{revision.revision}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Branch</DescriptionListTerm>
                <DescriptionListDescription>{revision.branch}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Upstream</DescriptionListTerm>
                <DescriptionListDescription>{revision.upstream}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>State</DescriptionListTerm>
                <DescriptionListDescription>
                  {revision.divergence}; checkout {revision.checkout}
                </DescriptionListDescription>
              </DescriptionListGroup>
              {update.candidateCommit ? (
                <DescriptionListGroup>
                  <DescriptionListTerm>Candidate</DescriptionListTerm>
                  <DescriptionListDescription>{update.candidateCommit}</DescriptionListDescription>
                </DescriptionListGroup>
              ) : null}
              {update.currentSystem ? (
                <DescriptionListGroup>
                  <DescriptionListTerm>Current system</DescriptionListTerm>
                  <DescriptionListDescription>{update.currentSystem}</DescriptionListDescription>
                </DescriptionListGroup>
              ) : null}
            </DescriptionList>
          )}
          {manualRecovery?.status === "manual-recovery-required" ? (
            <Alert variant="danger" isInline title="Manual recovery required">
              <p>{manualRecovery.reason || "Automatic rollback was incomplete."}</p>
              <p>Candidate: {manualRecovery.candidateCommit || "unknown"} · System: {manualRecovery.oldSystem || "unknown"}</p>
              {manualRecovery.stateSnapshot ? <p>State snapshot: {manualRecovery.stateSnapshot}</p> : null}
            </Alert>
          ) : null}
          {applianceBusy ? (
            <Alert variant="info" isInline title="Update in progress">
              nas-update is running. Progress, health checks, and journal are available in system logs.
              {busy ? <Spinner size="sm" aria-label="Update in progress" /> : null}
            </Alert>
          ) : null}
          <Title headingLevel="h3">Inspection (read-only)</Title>
          <p>These operations never mutate source or system state.</p>
          <div className="nas-actions nas-actions--wrap">
            {READ_ONLY.map((operation) => (
              <Button
                key={operation}
                variant="secondary"
                isDisabled={busy}
                onClick={() => runSource(operation)}
              >
                {operation}
              </Button>
            ))}
          </div>
          <Title headingLevel="h3">Guarded deployment via nas-update</Title>
          <p>Candidate preparation, health checks, state capture, rollback, and recovery evidence belong exclusively to nas-update.</p>
          <div className="nas-actions nas-actions--wrap">
            {UPDATE_OPS.map(({operation, label}) => (
              <Button
                key={operation}
                variant="primary"
                isDisabled={busy || applianceBusy}
                onClick={() => runUpdate(operation)}
              >
                {label}
              </Button>
            ))}
          </div>
        </CardBody>
      </Card>
      {result ? (
        <Card>
          <CardBody>
            <CardTitle>Last result</CardTitle>
            <OutputBlock>{pretty(result)}</OutputBlock>
          </CardBody>
        </Card>
      ) : null}
    </>
  );
}
