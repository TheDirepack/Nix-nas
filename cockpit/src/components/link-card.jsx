import React from "react";
import {Button, Card, CardBody, CardHeader, CardTitle} from "@patternfly/react-core";

export function LinkCard({entry}) {
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
