import React from "react";
import {Button, Title} from "@patternfly/react-core";

export function SectionHeader({title, hint, actionLabel, onAction, actionDisabled}) {
  return (
    <div className="nas-section-header">
      <div>
        <Title headingLevel="h2">{title}</Title>
        {hint ? <p>{hint}</p> : null}
      </div>
      {actionLabel ? (
        <Button variant="secondary" onClick={onAction} isDisabled={actionDisabled}>
          {actionLabel}
        </Button>
      ) : null}
    </div>
  );
}
