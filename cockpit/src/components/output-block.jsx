import React from "react";

export function OutputBlock({children}) {
  return (
    <pre className="nas-pre" tabIndex={0}>
      {children}
    </pre>
  );
}
