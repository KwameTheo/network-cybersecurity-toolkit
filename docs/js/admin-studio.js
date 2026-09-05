/**
 * AegisVault Studio - Software Creator & Management Studio
 * Enables Kwame Theo to add and publish new software creations via a visual UI.
 */

document.addEventListener("DOMContentLoaded", () => {
  setupStudioListeners();
});

function openStudioModal() {
  const modal = document.getElementById("studio-modal");
  if (!modal) return;
  modal.classList.add("active");
  updateStudioPreview();
  if (window.lucide) window.lucide.createIcons();
}

function closeStudioModal() {
  const modal = document.getElementById("studio-modal");
  if (modal) modal.classList.remove("active");
}

function setupStudioListeners() {
  const modal = document.getElementById("studio-modal");
  if (modal) {
    modal.addEventListener("click", (e) => {
      if (e.target === modal) closeStudioModal();
    });
  }

  // Live input synchronization for the preview card
  const inputIds = [
    "studio-title",
    "studio-version",
    "studio-tagline",
    "studio-category",
    "studio-platform",
    "studio-tags",
    "studio-icon"
  ];

  inputIds.forEach((id) => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener("input", updateStudioPreview);
      el.addEventListener("change", updateStudioPreview);
    }
  });

  // Form submission
  const form = document.getElementById("studio-form");
  if (form) {
    form.addEventListener("submit", handleSoftwarePublish);
  }
}

function updateStudioPreview() {
  const title = document.getElementById("studio-title")?.value || "Software Name";
  const version = document.getElementById("studio-version")?.value || "v1.0.0";
  const tagline = document.getElementById("studio-tagline")?.value || "Enter a compelling description or tagline for your software tool...";
  const platform = document.getElementById("studio-platform")?.value || "Windows 10 / 11";
  const icon = document.getElementById("studio-icon")?.value || "shield";
  const rawTags = document.getElementById("studio-tags")?.value || "Python, Security, Tool";
  
  const tagsArray = rawTags
    .split(",")
    .map((t) => t.trim())
    .filter((t) => t.length > 0)
    .slice(0, 4);

  const previewTitle = document.getElementById("preview-title");
  const previewVersion = document.getElementById("preview-version");
  const previewTagline = document.getElementById("preview-tagline");
  const previewPlatform = document.getElementById("preview-platform");
  const previewTags = document.getElementById("preview-tags");
  const previewIcon = document.getElementById("preview-icon-wrapper");

  if (previewTitle) previewTitle.textContent = title;
  if (previewVersion) previewVersion.textContent = version;
  if (previewTagline) previewTagline.textContent = tagline;
  if (previewPlatform) previewPlatform.textContent = platform;

  if (previewTags) {
    previewTags.innerHTML = tagsArray
      .map(
        (t) =>
          `<span class="px-2 py-0.5 text-xs font-mono rounded bg-slate-800/80 text-sky-300 border border-slate-700/50">${t}</span>`
      )
      .join("");
  }

  if (previewIcon) {
    previewIcon.innerHTML = `<i data-lucide="${icon}" class="w-6 h-6"></i>`;
    if (window.lucide) window.lucide.createIcons();
  }
}

function handleSoftwarePublish(e) {
  e.preventDefault();

  const title = document.getElementById("studio-title")?.value.trim();
  const version = document.getElementById("studio-version")?.value.trim() || "v1.0.0";
  const tagline = document.getElementById("studio-tagline")?.value.trim();
  const category = document.getElementById("studio-category")?.value || "security-network";
  const platform = document.getElementById("studio-platform")?.value.trim() || "Windows 10 / 11";
  const icon = document.getElementById("studio-icon")?.value || "shield";
  const rawTags = document.getElementById("studio-tags")?.value.trim() || "";
  const downloadUrl = document.getElementById("studio-download")?.value.trim() || "";
  const githubUrl = document.getElementById("studio-github")?.value.trim() || "";
  const fileSize = document.getElementById("studio-size")?.value.trim() || "Standalone";
  const sha256 = document.getElementById("studio-sha256")?.value.trim() || "";
  const summary = document.getElementById("studio-summary")?.value.trim() || tagline;
  const rawFeatures = document.getElementById("studio-features")?.value.trim() || "";

  if (!title || !tagline) {
    alert("Please enter at least a Software Title and Tagline.");
    return;
  }

  const tags = rawTags
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);

  const features = rawFeatures
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const parts = line.split(":");
      if (parts.length > 1) {
        return { name: parts[0].trim(), description: parts.slice(1).join(":").trim() };
      }
      return { name: line, description: "Core operational capability." };
    });

  const id = title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

  const newSoftware = {
    id: id || `software-${Date.now()}`,
    title: title,
    tagline: tagline,
    version: version,
    releaseDate: new Date().toISOString().split("T")[0],
    status: "Latest",
    featured: false,
    category: category,
    platform: platform,
    icon: icon,
    badge: "Community Release",
    author: "Kwame_Theo",
    githubUrl: githubUrl,
    downloadUrl: downloadUrl,
    fileSize: fileSize,
    sha256: sha256,
    summary: summary,
    tags: tags.length ? tags : ["Tool", "Software"],
    stats: {
      modules: features.length || 1,
      tests: "Verified",
      architecture: "Production Ready",
      security: "Hardened"
    },
    features: features.length ? features : [{ name: "Core Feature", description: tagline }],
    requirements: [platform, "No external dependencies required."],
    changelog: [`${version} - Initial release.`]
  };

  // Add to catalog and save
  const currentCatalog = getSoftwareCatalog();
  // Prepend new software so it appears first
  const updatedCatalog = [newSoftware, ...currentCatalog.filter((s) => s.id !== newSoftware.id)];
  saveSoftwareCatalog(updatedCatalog);

  // Re-render UI
  initSoftwareCatalog();

  // Show Export JSON dialog or prompt
  showExportModal(newSoftware);

  // Close creator modal
  closeStudioModal();
}

function showExportModal(softwareItem) {
  const jsonString = JSON.stringify(softwareItem, null, 2);
  const promptModal = document.getElementById("export-modal");
  const exportArea = document.getElementById("export-json-area");

  if (promptModal && exportArea) {
    exportArea.value = jsonString;
    promptModal.classList.add("active");
  } else {
    alert("Software published to your browser catalog successfully!");
  }
}

function closeExportModal() {
  const modal = document.getElementById("export-modal");
  if (modal) modal.classList.remove("active");
}

function copyExportJson() {
  const exportArea = document.getElementById("export-json-area");
  const copyBtn = document.getElementById("copy-export-btn");
  if (!exportArea) return;

  navigator.clipboard.writeText(exportArea.value).then(() => {
    if (copyBtn) {
      const orig = copyBtn.innerHTML;
      copyBtn.innerHTML = `<i data-lucide="check" class="w-4 h-4 text-emerald-400"></i> Copied to Clipboard!`;
      if (window.lucide) window.lucide.createIcons();
      setTimeout(() => {
        copyBtn.innerHTML = orig;
        if (window.lucide) window.lucide.createIcons();
      }, 2500);
    }
  });
}

function handleResetCatalog() {
  if (confirm("Reset software catalog back to original default entries?")) {
    resetSoftwareCatalogToDefault();
    initSoftwareCatalog();
    alert("Catalog reset to default.");
  }
}
