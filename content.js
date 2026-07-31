(function collectPageEvidence() {
  function safeText(value, maxLength = 500) {
    if (value === null || value === undefined) return "";
    return String(value).replace(/\s+/g, " ").trim().slice(0, maxLength);
  }

  function safeUrl(value) {
    try {
      return value ? String(value) : "";
    } catch (_e) {
      return "";
    }
  }

  function getCookieCountOnly() {
    try {
      if (!document.cookie) return 0;
      return document.cookie.split(";").filter(Boolean).length;
    } catch (_e) {
      return null;
    }
  }

  function getStorageCount(storage) {
    try {
      return storage ? storage.length : null;
    } catch (_e) {
      return null;
    }
  }

  function getHeadings() {
    return Array.from(document.querySelectorAll("h1,h2,h3,h4,h5,h6")).map((h, index) => ({
      index,
      level: h.tagName.toLowerCase(),
      text: safeText(h.innerText || h.textContent, 500)
    }));
  }

  function getForms() {
    return Array.from(document.forms).map((form, index) => ({
      index,
      id: safeText(form.id, 100),
      name: safeText(form.name, 100),
      method: safeText(form.method, 20),
      action: safeUrl(form.action),
      input_count: form.querySelectorAll("input, textarea, select, button").length,
      input_types: Array.from(form.querySelectorAll("input, textarea, select, button")).map(el => ({
        tag: el.tagName.toLowerCase(),
        type: safeText(el.getAttribute("type") || "", 50),
        name_present: Boolean(el.getAttribute("name")),
        id_present: Boolean(el.id),
        value_collected: false
      }))
    }));
  }

  function getButtons() {
    return Array.from(document.querySelectorAll("button, input[type='button'], input[type='submit'], [role='button']")).map((button, index) => ({
      index,
      tag: button.tagName.toLowerCase(),
      type: safeText(button.getAttribute("type") || "", 50),
      text: safeText(button.innerText || button.value || button.getAttribute("aria-label") || "", 300),
      aria_label: safeText(button.getAttribute("aria-label") || "", 300),
      value_collected: false
    }));
  }

  function getFrames() {
    return Array.from(document.querySelectorAll("iframe, frame")).map((frame, index) => ({
      index,
      tag: frame.tagName.toLowerCase(),
      src: safeUrl(frame.src),
      title: safeText(frame.title, 300),
      name: safeText(frame.name, 100),
      sandbox: safeText(frame.getAttribute("sandbox") || "", 300),
      allow: safeText(frame.getAttribute("allow") || "", 300)
    }));
  }

  function getResourceInventory() {
    return {
      scripts: Array.from(document.scripts).map((s, index) => ({
        index,
        src: safeUrl(s.src),
        type: safeText(s.type, 100),
        async: Boolean(s.async),
        defer: Boolean(s.defer),
        inline: !s.src
      })),
      stylesheets: Array.from(document.querySelectorAll("link[rel~='stylesheet']")).map((l, index) => ({
        index,
        href: safeUrl(l.href),
        media: safeText(l.media || "", 100)
      })),
      media: Array.from(document.querySelectorAll("video, audio, source, track")).map((m, index) => ({
        index,
        tag: m.tagName.toLowerCase(),
        src: safeUrl(m.src),
        type: safeText(m.type || "", 100)
      })),
      canvas_count: document.querySelectorAll("canvas").length,
      shadow_host_count: Array.from(document.querySelectorAll("*")).filter(el => el.shadowRoot).length
    };
  }

  function getPerformanceSummary() {
    let navigation = null;
    let resources = [];

    try {
      const navEntries = performance.getEntriesByType("navigation");
      if (navEntries && navEntries[0]) {
        const n = navEntries[0];
        navigation = {
          name: safeUrl(n.name),
          type: n.type,
          startTime: n.startTime,
          duration: n.duration,
          domContentLoadedEventEnd: n.domContentLoadedEventEnd,
          loadEventEnd: n.loadEventEnd,
          redirectCount: n.redirectCount,
          transferSize: n.transferSize,
          encodedBodySize: n.encodedBodySize,
          decodedBodySize: n.decodedBodySize,
          nextHopProtocol: n.nextHopProtocol || ""
        };
      }
    } catch (_e) {}

    try {
      resources = performance.getEntriesByType("resource").map((r, index) => ({
        index,
        name: safeUrl(r.name),
        initiatorType: r.initiatorType || "",
        duration: r.duration,
        transferSize: r.transferSize,
        encodedBodySize: r.encodedBodySize,
        decodedBodySize: r.decodedBodySize,
        nextHopProtocol: r.nextHopProtocol || ""
      }));
    } catch (_e) {}

    return {
      navigation,
      resources,
      note: "Performance entries are browser-observed resource timing records. Request headers, cookies, credential values, and local/source IP address are not collected."
    };
  }

  const links = Array.from(document.links).map((link, index) => ({
    index,
    text: safeText(link.innerText || link.textContent, 500),
    href: safeUrl(link.href),
    rel: safeText(link.rel, 100),
    target: safeText(link.target, 50)
  }));

  const images = Array.from(document.images).map((img, index) => ({
    index,
    src: safeUrl(img.currentSrc || img.src),
    declared_src: safeUrl(img.src),
    alt: safeText(img.alt, 500),
    width: img.naturalWidth || null,
    height: img.naturalHeight || null,
    displayed_width: img.clientWidth || null,
    displayed_height: img.clientHeight || null,
    binary_preserved: false
  }));

  const metaTags = Array.from(document.querySelectorAll("meta")).map((meta, index) => ({
    index,
    name: meta.getAttribute("name"),
    property: meta.getAttribute("property"),
    http_equiv: meta.getAttribute("http-equiv"),
    content: meta.getAttribute("content")
  }));

  return {
    observed_url_from_page: window.location.href,
    title: document.title,
    html: document.documentElement.outerHTML,
    text: document.body ? document.body.innerText : "",
    canonical_url: document.querySelector("link[rel='canonical']")?.href || null,
    referrer: document.referrer || "",
    page_dimensions: {
      scroll_width: document.documentElement.scrollWidth,
      scroll_height: document.documentElement.scrollHeight,
      client_width: document.documentElement.clientWidth,
      client_height: document.documentElement.clientHeight
    },
    viewport: {
      inner_width: window.innerWidth,
      inner_height: window.innerHeight,
      device_pixel_ratio: window.devicePixelRatio
    },
    browser_environment: {
      user_agent: navigator.userAgent,
      platform: navigator.platform,
      language: navigator.language,
      languages: Array.isArray(navigator.languages) ? navigator.languages : [],
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      cookie_enabled: navigator.cookieEnabled,
      online: navigator.onLine,
      do_not_track: navigator.doNotTrack || window.doNotTrack || navigator.msDoNotTrack || null,
      screen: {
        width: window.screen?.width || null,
        height: window.screen?.height || null,
        avail_width: window.screen?.availWidth || null,
        avail_height: window.screen?.availHeight || null,
        color_depth: window.screen?.colorDepth || null,
        pixel_depth: window.screen?.pixelDepth || null
      },
      privacy_note: "Hardware concurrency, device memory, local IP address, public IP address, cookie values, credential values, and local file paths are not collected."
    },
    storage_inventory: {
      cookies: {
        count: getCookieCountOnly(),
        names_collected: false,
        values_collected: false
      },
      localStorage: {
        count: getStorageCount(window.localStorage),
        keys_collected: false,
        values_collected: false
      },
      sessionStorage: {
        count: getStorageCount(window.sessionStorage),
        keys_collected: false,
        values_collected: false
      },
      privacy_note: "Only counts are collected. Cookie values, cookie names, localStorage keys, localStorage values, sessionStorage keys, and sessionStorage values are not stored."
    },
    dom_summary: {
      headings: getHeadings(),
      buttons: getButtons(),
      forms: getForms(),
      frames: getFrames()
    },
    resource_inventory: getResourceInventory(),
    performance_summary: getPerformanceSummary(),
    links,
    images,
    metaTags
  };
})();
