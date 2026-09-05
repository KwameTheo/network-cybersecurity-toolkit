/**
 * AegisVault Studio - Main Application Logic
 * Handles catalog rendering, instant search, category filtering, and detail modals.
 */

document.addEventListener("DOMContentLoaded", () => {
  // Initialize Lucide Icons
  if (window.lucide) {
    window.lucide.createIcons();
  }

  // Load and render catalog
  initSoftwareCatalog();

  // Setup search and filter listeners
  setupFilterListeners();

  // Setup detail modal listeners
  setupModalListeners();

  // Setup animated counters
  initCounters();
});

let currentFilter = "all";
let currentSearch = "";

function initSoftwareCatalog() {
  const catalog = getSoftwareCatalog();
  renderCatalogGrid(catalog);
  updateMetrics(catalog);
}

function updateMetrics(catalog) {
  const totalCountEl = document.getElementById("metric-total-software");
  if (totalCountEl) {
    totalCountEl.textContent = catalog.length;
  }
}

function renderCatalogGrid(catalog) {
  const gridContainer = document.getElementById("software-grid");
  if (!gridContainer) return;

  const filtered = catalog.filter((item) => {
    const matchesCategory =
      currentFilter === "all" || item.category === currentFilter;
    const query = currentSearch.toLowerCase().trim();
    const matchesSearch =
      !query ||
      item.title.toLowerCase().includes(query) ||
      item.tagline.toLowerCase().includes(query) ||
      item.summary.toLowerCase().includes(query) ||
      (item.tags && item.tags.some((t) => t.toLowerCase().includes(query)));

    return matchesCategory && matchesSearch;
  });

  if (filtered.length === 0) {
    gridContainer.innerHTML = `
      <div class="col-span-full py-16 text-center text-slate-400 glass-panel rounded-2xl border border-slate-800">
        <i data-lucide="search-x" class="w-12 h-12 mx-auto mb-3 text-slate-500"></i>
        <h3 class="text-xl font-bold text-white mb-1">No software found</h3>
        <p class="text-sm text-slate-400 max-w-md mx-auto">No tools matched your current search or category filter. Try refining your keywords or upload a new software tool.</p>
        <button onclick="resetFilters()" class="mt-4 px-4 py-2 bg-sky-500/20 hover:bg-sky-500/30 text-sky-400 text-sm font-semibold rounded-lg transition-colors border border-sky-500/30">
          Reset Filters
        </button>
      </div>
    `;
    if (window.lucide) window.lucide.createIcons();
    return;
  }

  gridContainer.innerHTML = filtered
    .map((item) => {
      const isFeatured = item.featured;
      const tagPills = (item.tags || [])
        .slice(0, 4)
        .map(
          (t) =>
            `<span class="px-2 py-0.5 text-xs font-mono rounded bg-slate-800/80 text-sky-300 border border-slate-700/50">${t}</span>`
        )
        .join("");

      return `
      <div class="glass-panel glass-panel-hover rounded-2xl p-6 flex flex-col justify-between relative overflow-hidden group ${
        isFeatured ? "border-sky-500/40" : "border-slate-800"
      }">
        ${
          isFeatured
            ? `<div class="absolute top-0 right-0 bg-gradient-to-l from-sky-500 to-indigo-600 text-white text-[10px] font-bold px-3 py-1 rounded-bl-lg uppercase tracking-wider shadow-md">
                Featured Flagship
              </div>`
            : ""
        }

        <div>
          <!-- Header & Badge -->
          <div class="flex items-start gap-4 mb-4">
            <div class="w-12 h-12 rounded-xl bg-gradient-to-br from-sky-500/20 to-indigo-500/20 border border-sky-500/30 flex items-center justify-center text-sky-400 shrink-0 group-hover:scale-105 transition-transform">
              <i data-lucide="${item.icon || 'shield'}" class="w-6 h-6"></i>
            </div>
            <div class="pr-6">
              <div class="flex items-center gap-2 flex-wrap mb-1">
                <span class="text-xs font-mono font-bold px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">${item.version}</span>
                <span class="text-xs text-slate-400 font-mono">${item.platform || 'Windows'}</span>
              </div>
              <h3 class="text-lg font-bold text-white group-hover:text-sky-400 transition-colors leading-snug">
                ${item.title}
              </h3>
            </div>
          </div>

          <!-- Description -->
          <p class="text-sm text-slate-300 mb-4 line-clamp-2 leading-relaxed">
            ${item.tagline || item.summary}
          </p>

          <!-- Tags -->
          <div class="flex flex-wrap gap-1.5 mb-6">
            ${tagPills}
          </div>
        </div>

        <!-- Footer Actions -->
        <div class="pt-4 border-t border-slate-800/80 flex items-center justify-between gap-3">
          <button onclick="openSoftwareDetails('${item.id}')" class="flex-1 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 hover:text-white text-xs font-semibold rounded-xl transition-all border border-slate-700 flex items-center justify-center gap-1.5">
            <i data-lucide="info" class="w-3.5 h-3.5 text-sky-400"></i>
            <span>Architecture & Specs</span>
          </button>

          ${
            item.downloadUrl
              ? `<a href="${item.downloadUrl}" target="_blank" class="px-4 py-2 bg-gradient-to-r from-sky-500 to-emerald-500 hover:from-sky-400 hover:to-emerald-400 text-slate-950 text-xs font-bold rounded-xl transition-all shadow-md hover:shadow-sky-500/25 flex items-center justify-center gap-1.5 shrink-0">
                  <i data-lucide="download" class="w-3.5 h-3.5"></i>
                  <span>Download</span>
                </a>`
              : `<a href="${item.githubUrl}" target="_blank" class="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white text-xs font-bold rounded-xl transition-all border border-slate-700 flex items-center justify-center gap-1.5 shrink-0">
                  <i data-lucide="github" class="w-3.5 h-3.5"></i>
                  <span>Source</span>
                </a>`
          }
        </div>
      </div>
    `;
    })
    .join("");

  if (window.lucide) {
    window.lucide.createIcons();
  }
}

function setupFilterListeners() {
  const searchInput = document.getElementById("search-input");
  if (searchInput) {
    searchInput.addEventListener("input", (e) => {
      currentSearch = e.target.value;
      const catalog = getSoftwareCatalog();
      renderCatalogGrid(catalog);
    });
  }

  const filterBtns = document.querySelectorAll("[data-filter]");
  filterBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      filterBtns.forEach((b) => {
        b.classList.remove("bg-sky-500", "text-slate-950", "font-bold");
        b.classList.add("bg-slate-900", "text-slate-300", "hover:bg-slate-800");
      });
      btn.classList.remove("bg-slate-900", "text-slate-300", "hover:bg-slate-800");
      btn.classList.add("bg-sky-500", "text-slate-950", "font-bold");

      currentFilter = btn.getAttribute("data-filter");
      const catalog = getSoftwareCatalog();
      renderCatalogGrid(catalog);
    });
  });
}

function resetFilters() {
  currentFilter = "all";
  currentSearch = "";
  const searchInput = document.getElementById("search-input");
  if (searchInput) searchInput.value = "";

  const allBtn = document.querySelector('[data-filter="all"]');
  if (allBtn) allBtn.click();
}

// Software Deep-Dive Modal
function openSoftwareDetails(softwareId) {
  const catalog = getSoftwareCatalog();
  const item = catalog.find((s) => s.id === softwareId);
  if (!item) return;

  const modalBackdrop = document.getElementById("details-modal");
  const modalBody = document.getElementById("details-modal-body");
  if (!modalBackdrop || !modalBody) return;

  const featureItems = (item.features || [])
    .map(
      (f) => `
    <li class="flex items-start gap-3 p-3 rounded-xl bg-slate-900/60 border border-slate-800">
      <i data-lucide="check-circle" class="w-5 h-5 text-emerald-400 shrink-0 mt-0.5"></i>
      <div>
        <h5 class="text-sm font-bold text-white">${f.name}</h5>
        <p class="text-xs text-slate-300 mt-0.5">${f.description}</p>
      </div>
    </li>
  `
    )
    .join("");

  const changelogItems = (item.changelog || [])
    .map(
      (c) => `
    <li class="text-xs text-slate-300 flex items-center gap-2">
      <span class="w-1.5 h-1.5 rounded-full bg-sky-400"></span>
      <span>${c}</span>
    </li>
  `
    )
    .join("");

  modalBody.innerHTML = `
    <!-- Top Header -->
    <div class="flex items-start justify-between gap-4 pb-6 border-b border-slate-800">
      <div class="flex items-center gap-4">
        <div class="w-14 h-14 rounded-2xl bg-gradient-to-br from-sky-500/20 to-emerald-500/20 border border-sky-500/30 flex items-center justify-center text-sky-400">
          <i data-lucide="${item.icon || 'shield'}" class="w-8 h-8"></i>
        </div>
        <div>
          <div class="flex items-center gap-2 flex-wrap">
            <h2 class="text-xl md:text-2xl font-bold text-white">${item.title}</h2>
            <span class="px-2.5 py-0.5 text-xs font-mono font-bold rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">${item.version}</span>
          </div>
          <p class="text-xs md:text-sm text-slate-400 mt-1">${item.tagline}</p>
        </div>
      </div>
      <button onclick="closeSoftwareDetails()" class="p-2 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 transition-colors">
        <i data-lucide="x" class="w-6 h-6"></i>
      </button>
    </div>

    <!-- Quick Stats Grid -->
    <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 my-6">
      <div class="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800">
        <span class="text-[11px] uppercase tracking-wider text-slate-400 font-mono">Platform</span>
        <div class="text-sm font-bold text-white mt-0.5">${item.platform || 'Windows'}</div>
      </div>
      <div class="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800">
        <span class="text-[11px] uppercase tracking-wider text-slate-400 font-mono">Release Date</span>
        <div class="text-sm font-bold text-white mt-0.5">${item.releaseDate || 'Recent'}</div>
      </div>
      <div class="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800">
        <span class="text-[11px] uppercase tracking-wider text-slate-400 font-mono">Test Status</span>
        <div class="text-sm font-bold text-emerald-400 mt-0.5">${item.stats ? item.stats.tests : 'Verified'}</div>
      </div>
      <div class="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800">
        <span class="text-[11px] uppercase tracking-wider text-slate-400 font-mono">Author</span>
        <div class="text-sm font-bold text-sky-400 mt-0.5">${item.author || 'Kwame_Theo'}</div>
      </div>
    </div>

    <!-- Overview Text -->
    <div class="mb-6">
      <h4 class="text-sm font-bold uppercase tracking-wider text-sky-400 font-mono mb-2">Executive Summary</h4>
      <p class="text-sm text-slate-200 leading-relaxed">${item.summary}</p>
    </div>

    <!-- Core Features -->
    ${
      featureItems
        ? `
      <div class="mb-6">
        <h4 class="text-sm font-bold uppercase tracking-wider text-sky-400 font-mono mb-3">Key Capabilities & Modules</h4>
        <ul class="grid grid-cols-1 md:grid-cols-2 gap-3">
          ${featureItems}
        </ul>
      </div>
    `
        : ""
    }

    <!-- Cryptographic Provenance & Hash -->
    ${
      item.sha256
        ? `
      <div class="mb-6 p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono">
        <div class="flex items-center justify-between text-xs text-slate-400 mb-1">
          <span class="flex items-center gap-1.5 text-emerald-400">
            <i data-lucide="lock" class="w-3.5 h-3.5"></i> SHA-256 Provenance Checksum
          </span>
          <button onclick="copyToClipboard('${item.sha256}', this)" class="text-sky-400 hover:text-sky-300 flex items-center gap-1 text-[11px]">
            <i data-lucide="copy" class="w-3 h-3"></i> Copy
          </button>
        </div>
        <div class="text-xs text-slate-300 break-all">${item.sha256}</div>
      </div>
    `
        : ""
    }

    <!-- Action Bar -->
    <div class="pt-4 border-t border-slate-800 flex flex-wrap items-center justify-end gap-3">
      ${
        item.githubUrl
          ? `<a href="${item.githubUrl}" target="_blank" class="px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-white text-xs font-bold rounded-xl transition-all border border-slate-700 flex items-center gap-2">
              <i data-lucide="github" class="w-4 h-4"></i>
              <span>GitHub Repository</span>
            </a>`
          : ""
      }
      ${
        item.downloadUrl
          ? `<a href="${item.downloadUrl}" target="_blank" class="px-6 py-2.5 bg-gradient-to-r from-sky-500 to-emerald-500 hover:from-sky-400 hover:to-emerald-400 text-slate-950 text-xs font-bold rounded-xl transition-all shadow-lg hover:shadow-sky-500/20 flex items-center gap-2">
              <i data-lucide="download" class="w-4 h-4"></i>
              <span>Download Release (${item.fileSize || 'Latest'})</span>
            </a>`
          : ""
      }
    </div>
  `;

  modalBackdrop.classList.add("active");
  if (window.lucide) window.lucide.createIcons();
}

function closeSoftwareDetails() {
  const modalBackdrop = document.getElementById("details-modal");
  if (modalBackdrop) modalBackdrop.classList.remove("active");
}

function setupModalListeners() {
  const modalBackdrop = document.getElementById("details-modal");
  if (modalBackdrop) {
    modalBackdrop.addEventListener("click", (e) => {
      if (e.target === modalBackdrop) {
        closeSoftwareDetails();
      }
    });
  }

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      closeSoftwareDetails();
      if (window.closeStudioModal) window.closeStudioModal();
    }
  });
}

function copyToClipboard(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const original = btn.innerHTML;
    btn.innerHTML = `<i data-lucide="check" class="w-3 h-3 text-emerald-400"></i> Copied!`;
    if (window.lucide) window.lucide.createIcons();
    setTimeout(() => {
      btn.innerHTML = original;
      if (window.lucide) window.lucide.createIcons();
    }, 2000);
  });
}

function initCounters() {
  // Can be expanded with smooth number counters
}
