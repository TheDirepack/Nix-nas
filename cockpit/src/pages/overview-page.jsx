import React from "react";
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  Gallery,
  GalleryItem,
} from "@patternfly/react-core";
import {StatusLabel} from "../components/status-label.jsx";
import {OutputBlock} from "../components/output-block.jsx";
import {setupModel, managedServiceRows} from "../view-model.js";

export function OverviewPage({data, refresh, busy}) {
  const setup = setupModel(data || {});
  const services = managedServiceRows(data || {});
  const running = services.filter((service) => service.running).length;
  const zfsHealthy = data?.zfs?.healthy === true;
  const cards = [
    {
      title: "Appliance",
      body: (
        <>
          <p>
            <strong>{data?.host || "NAS"}</strong>
          </p>
          <p>
            Protected services:{" "}
            <StatusLabel ok={data?.protectedReady === true}>
              {data?.protectedReady ? "ready" : "locked"}
            </StatusLabel>
          </p>
          <p>
            First start: <StatusLabel ok={setup.complete}>{setup.status}</StatusLabel>
          </p>
        </>
      ),
    },
    {
      title: "Managed Services V2",
      body: (
        <>
          <p>{services.length} services in the current authority.</p>
          <p>{running} native owner units currently active.</p>
          <Button variant="secondary" onClick={refresh} isDisabled={busy}>
            Refresh
          </Button>
        </>
      ),
    },
    {
      title: "ZFS",
      body: (
        <>
          <p>
            <StatusLabel ok={zfsHealthy}>
              {zfsHealthy ? "healthy" : "attention required"}
            </StatusLabel>
          </p>
          <OutputBlock>{data?.zfs?.summary || "Unavailable"}</OutputBlock>
          <OutputBlock>{data?.zfs?.dataset || ""}</OutputBlock>
        </>
      ),
    },
    {
      title: "Failures",
      body:
        Array.isArray(data?.failedUnits) && data.failedUnits.length ? (
          <OutputBlock>{data.failedUnits.join("\n")}</OutputBlock>
        ) : (
          <p>No failed units reported.</p>
        ),
    },
  ];
  return (
    <Gallery hasGutter minWidths={{default: "100%", sm: "320px"}}>
      {cards.map((card) => (
        <GalleryItem key={card.title}>
          <Card>
            <CardHeader>
              <CardTitle>{card.title}</CardTitle>
            </CardHeader>
            <CardBody>{card.body}</CardBody>
          </Card>
        </GalleryItem>
      ))}
    </Gallery>
  );
}
