/**
 * ContainmentTab — Component wrapper for ContainmentControls.
 * Provides live feedback for OS containment actions (Isolate Host, Kill Process, Quarantine File).
 */
import React from "react";
import ContainmentControls from "./ContainmentControls";

export default function ContainmentTab(props) {
  return <ContainmentControls {...props} />;
}
