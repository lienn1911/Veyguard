
import React from "react";

export default function Recommendations({
  recommendations = [],
  decisions = {},
  onDecision,
  saving = false,
}) {
  return (
    <section className="recommendations-section">
      <h3>Next-Step Recommendations</h3>

      {recommendations.length === 0 ? (
        <p>No recommendations available.</p>
      ) : (
        <div className="recommendation-list">
          {recommendations.map((rec) => {
            const decision = decisions[rec.id];

            return (
              <div className="recommendation-item" key={rec.id}>
                <p><strong>{rec.description}</strong></p>

                <small>
                  Evidence: {rec.evidence_ids.join(", ")}
                </small>

                <div className="recommendation-actions">
                  {decision ? (
                    <p>
                      Status: <strong>{decision}</strong>
                    </p>
                  ) : (
                    <>
                      <button
                        type="button"
                        disabled={saving || !onDecision}
                        onClick={() => onDecision(rec.id, "APPROVED")}
                      >
                        Approve
                      </button>

                      <button
                        type="button"
                        disabled={saving || !onDecision}
                        onClick={() => onDecision(rec.id, "REJECTED")}
                      >
                        Reject
                      </button>
                    </>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}
