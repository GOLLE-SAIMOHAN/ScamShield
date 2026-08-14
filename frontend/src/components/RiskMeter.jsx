import { useEffect, useState } from "react";

export default function RiskMeter({ score = 0, classification = "Safe" }) {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    let start = 0;
    const end = Math.min(100, Math.max(0, score));
    if (end === 0) {
      setAnimatedScore(0);
      return;
    }
    const duration = 800; // ms
    const increment = end / (duration / 16); // ~60fps
    const timer = setInterval(() => {
      start += increment;
      if (start >= end) {
        setAnimatedScore(end);
        clearInterval(timer);
      } else {
        setAnimatedScore(Math.floor(start));
      }
    }, 16);

    return () => clearInterval(timer);
  }, [score]);

  // Color selection based on the score
  const getColor = (s) => {
    if (s >= 85) return "var(--color-risk-critical)";
    if (s >= 65) return "var(--color-risk-high)";
    if (s >= 40) return "var(--color-risk-medium)";
    if (s >= 20) return "var(--color-risk-low)";
    return "var(--color-risk-safe)";
  };

  const getTextColorClass = (s) => {
    const norm = s.toLowerCase();
    if (norm.includes("malicious")) return "text-danger";
    if (norm.includes("high")) return "text-warning";
    if (norm.includes("medium")) return "text-info";
    if (norm.includes("low")) return "text-info-emphasis";
    return "text-success";
  };

  const color = getColor(animatedScore);
  const radius = 55;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (circumference * animatedScore) / 100;

  const riskClassName = getTextColorClass(classification);

  return (
    <div className="risk-meter-shell">
      <div className="risk-meter-ring">
        <svg width="150" height="150" viewBox="0 0 150 150" aria-label="Risk meter">
          <circle
            cx="75"
            cy="75"
            r={radius}
            fill="transparent"
            stroke="rgba(255,255,255,0.06)"
            strokeWidth="10"
          />
          <circle
            cx="75"
            cy="75"
            r={radius}
            fill="transparent"
            stroke={color}
            strokeWidth="10"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            style={{ transition: "stroke-dashoffset 0.1s ease-out, stroke 0.3s" }}
            transform="rotate(-90 75 75)"
          />
        </svg>
        <div className="risk-meter-value-wrap">
          <span className="risk-meter-value">{animatedScore}</span>
          <span className="risk-meter-label">Risk Score</span>
        </div>
      </div>
      <div className="risk-meter-meta">
        <h4 className={`risk-meter-classification ${riskClassName}`}>{classification}</h4>
        <span className="risk-meter-caption">Threat Classification</span>
      </div>
    </div>
  );
}
