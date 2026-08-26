import React, {useState} from "react";
import {
  Alert,
  Button,
  Card,
  CardBody,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Title,
} from "@patternfly/react-core";
import {apiInput} from "../api.js";
import {OutputBlock} from "../components/output-block.jsx";
import {pretty} from "../lib/format.js";
import {revisionModel} from "../view-model.js";

export function SourcePage({data, mutate, busy}) {
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
            </DescriptionList>
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
            <OutputBlock>{pretty(result)}</OutputBlock>
          </CardBody>
        </Card>
      ) : null}
    </>
  );
}
