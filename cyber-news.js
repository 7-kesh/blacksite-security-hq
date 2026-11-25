(() => {
  "use strict";
  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => Array.from(document.querySelectorAll(selector));
  let period = "daily";
  let payloads = { daily: null, weekly: null };
  const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, c => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  }[c]));
  const setText = (selector, value) => { const el = $(selector); if (el) el.textContent = value; };

  function render() {
    const host = $("#newsFeed");
    const payload = payloads[period];
    if (!host) return;
    if (!payload) {
      host.innerHTML = '<p class="empty">The ' + period + ' briefing is not available yet. Use Refresh to try again.</p>';
      return;
    }
    const category = $("#newsCategory")?.value || "all";
    const query = ($("#newsSearch")?.value || "").trim().toLowerCase();
    const stories = (payload.stories || []).filter(story =>
      (category === "all" || story.category === category) &&
      (!query || [story.title, story.summary, story.source, story.category].join(" ").toLowerCase().includes(query))
    );
    const generated = payload.generatedAt ? new Date(payload.generatedAt).toLocaleString() : "time unavailable";
    setText("#newsGenerated", (period === "daily" ? "Daily briefing" : "Weekly roundup") + " · Generated " + generated);
    const sources = payload.sources || [];
    setText("#newsSourceStatus", sources.filter(source => source.available).length + "/" + sources.length + " feeds online · " + (payload.storyCount || stories.length) + " stories collected");
    if (!stories.length) {
      host.innerHTML = '<p class="empty">No stories match this filter in the selected briefing.</p>';
      return;
    }
    host.innerHTML = stories.map(story => {
      const date = story.publishedAt ? new Date(story.publishedAt).toLocaleString() : "Date unavailable";
      const url = /^https?:\/\//i.test(story.url || "") ? escapeHtml(story.url) : "#";
      return '<article class="news-card"><div class="news-card-top"><span class="news-category">' +
        escapeHtml(story.category || "Security Industry") + '</span><span class="news-urgency ' +
        (story.urgency === "High attention" ? "attention" : "") + '">' + escapeHtml(story.urgency || "Monitor") +
        '</span></div><h3><a href="' + url + '" target="_blank" rel="noopener">' + escapeHtml(story.title) +
        '</a></h3><div class="news-byline">' + escapeHtml(story.source || "Security feed") + " · " + escapeHtml(date) +
        '</div>' + (story.summary ? '<p>' + escapeHtml(story.summary) + '</p>' : "") +
        '<div class="news-action"><b>Defender action</b><span>' +
        escapeHtml(story.defensiveAction || "Review the source and assess relevance to your environment.") +
        '</span></div><a class="news-read" href="' + url + '" target="_blank" rel="noopener">Read original report ↗</a></article>';
    }).join("");
  }

  async function load(nextPeriod = period) {
    period = nextPeriod;
    $$("[data-news-period]").forEach(button => {
      const active = button.dataset.newsPeriod === period;
      button.classList.toggle("primary", active);
      button.classList.toggle("secondary", !active);
    });
    const host = $("#newsFeed");
    if (host) host.innerHTML = '<p class="empty">Fetching ' + period + ' briefing…</p>';
    setText("#newsGenerated", "Loading " + period + " briefing…");
    try {
      const url = new URL("data/" + period + ".json", document.baseURI);
      url.searchParams.set("v", String(Date.now()));
      const response = await fetch(url.href, { cache: "no-store" });
      if (!response.ok) throw new Error("News file returned HTTP " + response.status);
      const data = await response.json();
      if (!Array.isArray(data.stories)) throw new Error("News file has an unexpected format");
      payloads[period] = data;
      render();
    } catch (error) {
      if (host) host.innerHTML = '<p class="empty">Could not load the ' + period + ' briefing: ' + escapeHtml(error.message) + '. Check the site deployment and try Refresh.</p>';
      setText("#newsGenerated", "Briefing unavailable");
      setText("#newsSourceStatus", "");
      console.error("[BLACKSITE cyber news]", error);
    }
  }

  document.addEventListener("click", event => {
    const button = event.target.closest("[data-news-period]");
    if (button) load(button.dataset.newsPeriod);
    if (event.target.closest("#refreshNews")) load(period);
  });
  $("#newsCategory")?.addEventListener("change", render);
  $("#newsSearch")?.addEventListener("input", render);
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", () => load("daily"), { once: true });
  else load("daily");
})();