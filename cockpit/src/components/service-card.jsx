import React from "react";
import {
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  FormSelect,
  FormSelectOption,
  Label,
} from "@patternfly/react-core";
import {MODE_LABELS, managedServiceRuntimeText, managedServiceUnitState, mib} from "../view-model.js";
import {StatusLabel} from "./status-label.jsx";

export function ServiceCard({service, onMode, disabled}) {
  const modes = Array.isArray(service.allowedModes) ? service.allowedModes : ["off", "always"];
  return (
    <Card isCompact>
      <CardHeader>
        <CardTitle>{service.label || service.id}</CardTitle>
      </CardHeader>
      <CardBody>
        <div className="nas-card-row">
          <StatusLabel ok={service.healthy === true || service.effectiveMode === "on-demand"}>
            {managedServiceUnitState(service)}
          </StatusLabel>
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
          <div className="nas-field">
            <span>Lifecycle mode</span>
            <FormSelect
              aria-label={`${service.label || service.id} runtime policy`}
              value={service.requestedMode || "off"}
              isDisabled={disabled}
              onChange={(_event, value) => onMode(service.id, value)}
            >
              {modes.map((mode) => (
                <FormSelectOption key={mode} value={mode} label={MODE_LABELS[mode] || mode} />
              ))}
            </FormSelect>
          </div>
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
