import React, {useMemo} from "react";
import {Gallery, GalleryItem, Title} from "@patternfly/react-core";
import {LinkCard} from "../components/link-card.jsx";
import {managedApplicationLinks, staticLinks} from "../view-model.js";

export function ApplicationsPage({data}) {
  const managed = managedApplicationLinks(data || {});
  const staticEntries = staticLinks(data || {});
  const grouped = useMemo(() => {
    const result = new Map();
    for (const entry of managed) {
      if (!result.has(entry.category)) result.set(entry.category, []);
      result.get(entry.category).push(entry);
    }
    return result;
  }, [managed]);
  return (
    <>
      <Title headingLevel="h2">Applications</Title>
      <p>
        Application links are projected from Managed Services V2 route metadata; Caddy still
        enforces authorization on every request.
      </p>
      {[...grouped.entries()].map(([category, entries]) => (
        <section key={category} className="nas-section">
          <Title headingLevel="h3">{category}</Title>
          <Gallery hasGutter minWidths={{default: "100%", sm: "260px"}}>
            {entries.map((entry) => (
              <GalleryItem key={entry.id}>
                <LinkCard entry={entry} />
              </GalleryItem>
            ))}
          </Gallery>
        </section>
      ))}
      <section className="nas-section">
        <Title headingLevel="h3">Platform tools</Title>
        <Gallery hasGutter minWidths={{default: "100%", sm: "260px"}}>
          {staticEntries.map((entry) => (
            <GalleryItem key={entry.key}>
              <LinkCard entry={entry} />
            </GalleryItem>
          ))}
        </Gallery>
      </section>
    </>
  );
}
