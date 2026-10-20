
import React from "react";

export default function Guardrails({ result }) {
  if (!result) {
    return null;
  }

  return (
    <section className="guardrail-panel">
      <h3>Safe-Closure Guardrail</h3>

      <p>
        Status: <strong>{result.status}</strong>
      </p>

      {result.reasons?.map((reason, index) => (
        <p key={index}>{reason}</p>
      ))}
    </section>
  );
}
