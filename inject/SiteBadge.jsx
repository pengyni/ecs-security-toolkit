import React from "react";

export default function SiteBadge() {
  return (
    <div
      className="site-hardened-mark"
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 8,
        margin: "12px 0",
        padding: "6px 10px",
        border: "1px solid #c3c3c3",
        background: "#fff",
        color: "#191919",
        fontFamily: "Source Sans Pro, Arial, sans-serif",
        fontSize: 12,
        lineHeight: 1.2,
        userSelect: "none",
      }}
    >
      <span
        aria-hidden="true"
        style={{
          width: 8,
          height: 8,
          borderRadius: 8,
          background: "#02b757",
          display: "inline-block",
        }}
      />
      <span>Site hardened</span>
    </div>
  );
}
