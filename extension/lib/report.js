// ph-reqKO blocker: pure report-aggregation logic. No browser APIs here.

export const MAX_REPORT_EVENTS = 500;
export const MAX_QUEUE_EVENTS = 5000;

/**
 * Aggregates declarativeNetRequest matched-rule entries into report events.
 * Only HTTP(S) request URLs are counted; entries are grouped by the request
 * host (the blocked domain), counts summed. Initiator/page info is NOT sent.
 * entries: [{request: {url}, ...}]
 * Returns [{domain, count}] sorted by domain.
 */
export function aggregateMatchedRules(entries) {
  const counts = new Map();
  for (const entry of entries) {
    const url = entry && entry.request && entry.request.url;
    if (typeof url !== "string") continue;
    if (!url.startsWith("http://") && !url.startsWith("https://")) continue;
    let host;
    try {
      host = new URL(url).hostname;
    } catch (err) {
      continue; // unparseable URL: skip, never throw
    }
    if (host.length === 0) continue;
    counts.set(host, (counts.get(host) || 0) + 1);
  }
  return [...counts.entries()]
    .map(([domain, count]) => ({ domain, count }))
    .sort((a, b) => (a.domain < b.domain ? -1 : 1));
}

/**
 * Merges pending events into the existing queue (bounded): same-domain
 * counts are summed, the result is capped at MAX_QUEUE_EVENTS events by
 * dropping the smallest counts first. Returns the new queue.
 */
export function mergeQueue(queue, fresh) {
  const counts = new Map();
  for (const event of [...queue, ...fresh]) {
    if (typeof event.domain !== "string" || typeof event.count !== "number") continue;
    counts.set(event.domain, (counts.get(event.domain) || 0) + event.count);
  }
  let merged = [...counts.entries()]
    .map(([domain, count]) => ({ domain, count }))
    .sort((a, b) => (a.domain < b.domain ? -1 : 1));
  while (merged.length > MAX_QUEUE_EVENTS) {
    // Drop the smallest counts first: least information lost
    let smallest = 0;
    for (let i = 1; i < merged.length; i++) {
      if (merged[i].count < merged[smallest].count) smallest = i;
    }
    merged.splice(smallest, 1);
  }
  return merged;
}

/**
 * Stamps each pending event with the current unix time (seconds) and caps
 * the batch at MAX_REPORT_EVENTS events per request.
 */
export function buildReportBatch(pending, nowSeconds) {
  const batch = pending
    .slice(0, MAX_REPORT_EVENTS)
    .map((event) => ({ domain: event.domain, count: event.count, ts: nowSeconds }));
  const remaining = pending.slice(MAX_REPORT_EVENTS);
  return { batch, remaining };
}
