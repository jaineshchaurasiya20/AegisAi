/**
 * XAIModal — Wrapper around XAIExplanationModal for tree attribution and SHAP inspection.
 */
import React from "react";
import XAIExplanationModal from "./XAIExplanationModal";

export default function XAIModal(props) {
  return <XAIExplanationModal {...props} />;
}
