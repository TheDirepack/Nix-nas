import React from "react";
import {Label} from "@patternfly/react-core";

export function StatusLabel({ok, children}) {
  return <Label color={ok ? "green" : "orange"}>{children}</Label>;
}
