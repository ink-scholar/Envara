import React, { useEffect, useState } from "react";
import { Desktop } from "@phosphor-icons/react";
import { api } from "./client.js";

// One request per bundle path for the whole window; the main process answers
// only for bundles the catalog listed or a saved binding holds.
const icons = new Map();
function iconFor(path) {
  if (!icons.has(path)) {
    const entry = { value: undefined };
    entry.promise = api.call("applicationIcon", { path }).then(result => typeof result?.icon === "string" && result.icon.startsWith("data:image/png;base64,") ? result.icon : null, () => null)
      .then(value => { entry.value = value; return value; });
    icons.set(path, entry);
  }
  return icons.get(path);
}

/** The application's own icon, or the generic glyph while it loads or when the
 * system has none. */
export function ApplicationIcon({ path, size = 42, className = "application-icon" }) {
  const usable = api.isDesktop === true && typeof path === "string" && path.length > 0;
  const [icon, setIcon] = useState(() => usable ? icons.get(path)?.value ?? null : null);
  useEffect(() => {
    if (!usable) { setIcon(null); return; }
    let current = true; const entry = iconFor(path);
    if (entry.value !== undefined) setIcon(entry.value);
    else entry.promise.then(value => { if (current) setIcon(value); });
    return () => { current = false; };
  }, [path, usable]);
  return <span className={`${className}${icon ? " has-image" : ""}`} style={{ width: size, height: size }} aria-hidden="true">
    {icon ? <img src={icon} alt="" width={size} height={size} draggable={false} /> : <Desktop size={Math.round(size * 0.56)} />}
  </span>;
}
