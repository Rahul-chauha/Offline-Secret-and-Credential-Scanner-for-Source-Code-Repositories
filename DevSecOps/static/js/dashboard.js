// Offline Secret and Credential Scanner - Client Dashboard Interactive Engine
// Academic Session 2026-27 | II-Year Mini Project

document.addEventListener('DOMContentLoaded', () => {
  initFileUpload();
  initFindingsEngine();
  initCopyActions();
});

// ============================================================================
// 1. Drag & Drop Archive Ingestion Engine
// ============================================================================
function initFileUpload() {
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('project_zip');
  const browseBtn = document.getElementById('browseBtn');
  const uploadForm = document.getElementById('uploadForm');
  const fileNameDisplay = document.getElementById('selectedFileName');
  const submitBtn = document.getElementById('submitBtn');
  const localFolderInput = document.getElementById('local_folder_path');
  const projectNameInput = document.getElementById('project_name');

  if (!dropzone || !fileInput) return;

  function updateFileDisplay(file) {
    if (!file) return;

    if (!file.name.toLowerCase().endsWith('.zip')) {
      alert('Security Policy: Only .zip repository archive files are accepted for offline scanning.');
      fileInput.value = '';
      if (fileNameDisplay) {
        fileNameDisplay.style.display = 'none';
        fileNameDisplay.textContent = '';
      }
      return;
    }

    // Auto-populate project name if empty
    if (projectNameInput && !projectNameInput.value.trim()) {
      projectNameInput.value = file.name.replace(/\.zip$/i, '');
    }

    if (fileNameDisplay) {
      const sizeMB = (file.size / (1024 * 1024)).toFixed(2);
      fileNameDisplay.textContent = `Selected: ${file.name} (${sizeMB} MB)`;
      fileNameDisplay.style.display = 'block';
    }
  }

  if (browseBtn) {
    browseBtn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      fileInput.click();
    });
  }

  ['dragenter', 'dragover'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.remove('dragover');
    });
  });

  dropzone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    if (dt && dt.files && dt.files.length > 0) {
      const file = dt.files[0];
      try {
        fileInput.files = dt.files;
      } catch (err) {
        console.warn('DataTransfer fallback', err);
      }
      updateFileDisplay(file);
    }
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files && fileInput.files.length > 0) {
      updateFileDisplay(fileInput.files[0]);
    }
  });

  if (uploadForm) {
    uploadForm.addEventListener('submit', (e) => {
      const hasLocalFolder = localFolderInput && localFolderInput.value.trim().length > 0;
      const hasFile = fileInput.files && fileInput.files.length > 0;

      if (!hasFile && !hasLocalFolder) {
        e.preventDefault();
        alert('Please choose a repository .ZIP archive or specify a local directory path to scan.');
        return;
      }

      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = `
          <svg style="animation: spin 1s linear infinite; width:16px; height:16px; margin-right:8px; display:inline-block; vertical-align:middle;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
            <circle cx="12" cy="12" r="10" stroke-opacity="0.25"></circle>
            <path d="M12 2a10 10 0 0 1 10 10" stroke-linecap="round"></path>
          </svg>
          Scanning Offline Pipeline...
        `;
      }
    });
  }
}

// ============================================================================
// 2. Interactive Severity Filter, Search & Pagination Engine
// ============================================================================
function initFindingsEngine() {
  const findingCards = Array.from(document.querySelectorAll('.finding-card'));
  const filterButtons = document.querySelectorAll('.filter-btn');
  const searchInput = document.getElementById('findingSearch');
  const visibleCountEl = document.getElementById('visibleCount');
  const noMatchMsg = document.getElementById('noMatchMessage');

  // Pagination elements
  const paginationBar = document.getElementById('paginationBar');
  const prevBtn = document.getElementById('prevPageBtn');
  const nextBtn = document.getElementById('nextPageBtn');
  const pageNumbersContainer = document.getElementById('pageNumberButtons');
  const pageRangeEl = document.getElementById('pageRange');
  const totalMatchingEl = document.getElementById('totalMatching');
  const pageSizeSelect = document.getElementById('pageSizeSelect');

  if (findingCards.length === 0) return;

  let activeSeverity = 'all';
  let searchTerm = '';
  let currentPage = 1;
  let pageSize = 15;

  function getMatchingCards() {
    return findingCards.filter(card => {
      const cardSeverity = (card.getAttribute('data-severity') || '').toLowerCase();
      const cardText = card.textContent.toLowerCase();

      const matchSeverity = (activeSeverity === 'all' || cardSeverity === activeSeverity.toLowerCase());
      const matchSearch = (!searchTerm || cardText.includes(searchTerm));

      return matchSeverity && matchSearch;
    });
  }

  function renderPage() {
    const matchingCards = getMatchingCards();
    const totalMatching = matchingCards.length;

    // Update Counter
    if (visibleCountEl) visibleCountEl.textContent = totalMatching;
    if (totalMatchingEl) totalMatchingEl.textContent = totalMatching;

    // Empty state handling
    if (totalMatching === 0) {
      findingCards.forEach(c => c.style.display = 'none');
      if (noMatchMsg) noMatchMsg.style.display = 'block';
      if (paginationBar) paginationBar.style.display = 'none';
      return;
    } else {
      if (noMatchMsg) noMatchMsg.style.display = 'none';
    }

    // Determine pagination bounds
    const isAll = (pageSize === 'all');
    const effectivePageSize = isAll ? totalMatching : parseInt(pageSize, 10);
    const totalPages = isAll ? 1 : Math.ceil(totalMatching / effectivePageSize);

    if (currentPage > totalPages) currentPage = totalPages;
    if (currentPage < 1) currentPage = 1;

    const startIndex = (currentPage - 1) * effectivePageSize;
    const endIndex = isAll ? totalMatching : Math.min(startIndex + effectivePageSize, totalMatching);

    // Hide all, show matching subset for this page
    findingCards.forEach(c => c.style.display = 'none');
    for (let i = startIndex; i < endIndex; i++) {
      if (matchingCards[i]) {
        matchingCards[i].style.display = 'block';
      }
    }

    // Update pagination UI
    if (pageRangeEl) {
      pageRangeEl.textContent = `${startIndex + 1}–${endIndex}`;
    }

    if (paginationBar) {
      // Show pagination if more than 1 page or user selected size
      paginationBar.style.display = (totalPages > 1 || pageSize !== 'all') ? 'flex' : 'none';
    }

    if (prevBtn) prevBtn.disabled = (currentPage <= 1);
    if (nextBtn) nextBtn.disabled = (currentPage >= totalPages);

    // Render Page Number Buttons
    if (pageNumbersContainer) {
      pageNumbersContainer.innerHTML = '';

      // For <= 7 pages, show all numbers. For more, show compact window
      let pagesToShow = [];
      if (totalPages <= 7) {
        for (let i = 1; i <= totalPages; i++) pagesToShow.push(i);
      } else {
        pagesToShow = [1];
        let start = Math.max(2, currentPage - 1);
        let end = Math.min(totalPages - 1, currentPage + 1);

        if (start > 2) pagesToShow.push('...');
        for (let i = start; i <= end; i++) pagesToShow.push(i);
        if (end < totalPages - 1) pagesToShow.push('...');
        pagesToShow.push(totalPages);
      }

      pagesToShow.forEach(item => {
        if (item === '...') {
          const ellipsis = document.createElement('span');
          ellipsis.textContent = '...';
          ellipsis.style.padding = '0 6px';
          ellipsis.style.color = 'var(--text-muted)';
          ellipsis.style.fontSize = '12px';
          pageNumbersContainer.appendChild(ellipsis);
        } else {
          const pageBtn = document.createElement('button');
          pageBtn.type = 'button';
          pageBtn.className = `page-btn ${item === currentPage ? 'active' : ''}`;
          pageBtn.textContent = item;
          pageBtn.addEventListener('click', () => {
            currentPage = item;
            renderPage();
            scrollToFindingsTop();
          });
          pageNumbersContainer.appendChild(pageBtn);
        }
      });
    }
  }

  function scrollToFindingsTop() {
    const container = document.getElementById('findingsContainer');
    if (container) {
      const topPos = container.getBoundingClientRect().top + window.scrollY - 100;
      if (window.scrollY > topPos) {
        window.scrollTo({ top: topPos, behavior: 'smooth' });
      }
    }
  }

  // Filter category click
  filterButtons.forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      const filterVal = btn.getAttribute('data-filter') || 'all';

      filterButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      activeSeverity = filterVal;
      currentPage = 1;
      renderPage();
    });
  });

  // Search input typing
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      searchTerm = e.target.value.trim().toLowerCase();
      currentPage = 1;
      renderPage();
    });
  }

  // Previous / Next button clicks
  if (prevBtn) {
    prevBtn.addEventListener('click', () => {
      if (currentPage > 1) {
        currentPage--;
        renderPage();
        scrollToFindingsTop();
      }
    });
  }

  if (nextBtn) {
    nextBtn.addEventListener('click', () => {
      const matching = getMatchingCards();
      const effectiveSize = (pageSize === 'all') ? matching.length : parseInt(pageSize, 10);
      const totalPages = Math.ceil(matching.length / effectiveSize);
      if (currentPage < totalPages) {
        currentPage++;
        renderPage();
        scrollToFindingsTop();
      }
    });
  }

  // Page size select change
  if (pageSizeSelect) {
    pageSizeSelect.addEventListener('change', (e) => {
      pageSize = e.target.value;
      currentPage = 1;
      renderPage();
    });
  }

  // Initial render
  renderPage();
}

// ============================================================================
// 3. 1-Click Clipboard Copying with Visual Feedback
// ============================================================================
function copyToClipboard(text, onSuccess) {
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(onSuccess).catch(err => {
      console.warn('Clipboard API error, fallback to execCommand', err);
      fallbackCopy(text, onSuccess);
    });
  } else {
    fallbackCopy(text, onSuccess);
  }
}

function fallbackCopy(text, onSuccess) {
  const textArea = document.createElement('textarea');
  textArea.value = text;
  textArea.style.position = 'fixed';
  textArea.style.left = '-999999px';
  textArea.style.top = '-999999px';
  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();
  try {
    document.execCommand('copy');
    if (onSuccess) onSuccess();
  } catch (err) {
    console.error('Fallback copy failed', err);
  }
  document.body.removeChild(textArea);
}

function initCopyActions() {
  // Snippet Copy
  document.querySelectorAll('.btn-copy-snippet').forEach(btn => {
    btn.addEventListener('click', () => {
      const snippet = btn.getAttribute('data-snippet') || '';
      if (!snippet) return;

      copyToClipboard(snippet, () => {
        const textSpan = btn.querySelector('span');
        const origText = textSpan ? textSpan.textContent : btn.textContent;
        if (textSpan) textSpan.textContent = 'Copied!';
        btn.style.color = '#34d399';

        setTimeout(() => {
          if (textSpan) textSpan.textContent = origText;
          btn.style.color = '';
        }, 1600);
      });
    });
  });

  // Path Copy
  document.querySelectorAll('.btn-copy-path').forEach(btn => {
    btn.addEventListener('click', () => {
      const pathText = btn.getAttribute('data-path') || '';
      if (!pathText) return;

      copyToClipboard(pathText, () => {
        const origHtml = btn.innerHTML;
        btn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#34d399" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
        btn.setAttribute('title', 'Copied!');

        setTimeout(() => {
          btn.innerHTML = origHtml;
          btn.setAttribute('title', 'Copy file path & line');
        }, 1600);
      });
    });
  });
}

// Global CSS Keyframe for Spinners
if (!document.getElementById('scanner-keyframes')) {
  const styleEl = document.createElement('style');
  styleEl.id = 'scanner-keyframes';
  styleEl.textContent = `
    @keyframes spin {
      from { transform: rotate(0deg); }
      to { transform: rotate(360deg); }
    }
  `;
  document.head.appendChild(styleEl);
}
