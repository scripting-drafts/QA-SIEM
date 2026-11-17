"use strict";

const $ = (selector) => document.querySelector(selector);

const STATUS = {
  reviewed: { text: "Reviewed", className: "ok" },
  pending: { text: "Pending", className: "warn" },
  "not-applicable": { text: "N/A", className: "" },
};

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text != null) element.textContent = String(text);
  return element;
}

function showError(message) {
  const error = $("#legal-error");
  error.textContent = message;
  error.classList.remove("hidden");
  $("#legal-content").classList.add("hidden");
}

function setText(selector, value) {
  $(selector).textContent = value == null || value === "" ? "—" : String(value);
}

function render(data) {
  const pending = (data.reviews || []).filter((review) => review.status === "pending");
  setText("#legal-product", data.product);
  setText("#legal-version", `Reviewed version ${data.reviewedVersion}`);
  setText("#legal-license", data.spdx);
  setText("#legal-reviewed", `Last reviewed ${data.lastReviewed}`);
  setText("#legal-status", pending.length ? "Review due" : "OK");
  setText("#legal-pending", pending.length
    ? `${pending.length} pending review${pending.length === 1 ? "" : "s"}`
    : "No pending reviews");
  const source = $("#legal-source");
  if (typeof data.source === "string" && /^https:\/\//.test(data.source)) {
    source.href = data.source;
    source.textContent = data.source;
  } else {
    source.removeAttribute("href");
    source.textContent = "—";
  }

  const components = $("#legal-components");
  components.replaceChildren();
  for (const component of data.components || []) {
    const row = document.createElement("tr");
    row.append(
      node("td", "", component.name),
      node("td", "muted", component.version || "—"),
      node("td", "", component.license),
      node("td", "muted", component.scope),
    );
    components.append(row);
  }
  setText("#legal-component-count", `${(data.components || []).length} components`);

  const reviews = $("#legal-reviews");
  reviews.replaceChildren();
  for (const review of data.reviews || []) {
    const item = node("div", "legal-item");
    const status = STATUS[review.status] || STATUS.pending;
    const pill = node("span", `legal-status ${status.className}`.trim(), status.text);
    const body = node("div", "legal-item-body");
    body.append(
      node("strong", "", `${review.category} · ${review.date}`),
      node("span", "muted", review.note),
    );
    item.append(pill, body);
    reviews.append(item);
  }
  setText("#legal-review-count", `${(data.reviews || []).length} reviews`);

  const documents = $("#legal-documents");
  documents.replaceChildren();
  for (const doc of data.documents || []) {
    const item = node("div", "legal-item");
    const body = node("div", "legal-item-body");
    body.append(
      node("strong", "", doc.label),
      node("span", "muted", doc.path),
    );
    item.append(node("span", "legal-status ok", "Doc"), body);
    documents.append(item);
  }

  $("#legal-error").classList.add("hidden");
  $("#legal-content").classList.remove("hidden");
}

async function load() {
  try {
    const response = await fetch("/legal.json", { cache: "no-store" });
    if (!response.ok) throw new Error(`legal manifest unavailable (${response.status})`);
    render(await response.json());
  } catch (error) {
    showError(String(error.message || error));
  }
}

load();
