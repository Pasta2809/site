(function() {
  // theme toggle
  const rootEl = document.documentElement;
  const savedTheme = localStorage.getItem('theme');
  if (savedTheme === 'dark') {
    rootEl.setAttribute('data-theme', 'dark');
  }
  const themeBtn = document.getElementById('theme-toggle');
  if (themeBtn) {
    themeBtn.addEventListener('click', () => {
      const current = rootEl.getAttribute('data-theme') || 'light';
      const next = current === 'light' ? 'dark' : 'light';
      rootEl.setAttribute('data-theme', next);
      localStorage.setItem('theme', next);
    });
  }

  // overlay menu
  const menuBtn = document.getElementById('menu-toggle');
  const menu = document.getElementById('overlay-menu');
  const menuClose = document.getElementById('menu-close');
  if (menuBtn && menu) {
    menuBtn.addEventListener('click', () => {
      menu.classList.add('open');
    });
  }
  if (menuClose && menu) {
    menuClose.addEventListener('click', () => {
      menu.classList.remove('open');
    });
  }

  // dashboard check-all
  const checkAll = document.getElementById('check-all');
  if (checkAll) {
    checkAll.addEventListener('change', () => {
      document.querySelectorAll('input[name="file_ids"]').forEach(cb => {
        cb.checked = checkAll.checked;
      });
    });
  }

  // admin_files edit modal
  const editModal = document.getElementById('file-edit-modal');
  if (editModal) {
    const editFileId = document.getElementById('edit-file-id');
    const editFileName = document.getElementById('edit-file-name');
    const editDesc = document.getElementById('edit-description');
    const editFolder = document.getElementById('edit-folder');
    const editCategory = document.getElementById('edit-category');
    const editExpires = document.getElementById('edit-expires-date');
    const cancelBtn = document.getElementById('edit-cancel-btn');
    const backdrop = editModal.querySelector('.modal-backdrop');

    function openModal(row) {
      const id = row.getAttribute('data-file-id');
      const name = row.getAttribute('data-file-name') || '';
      const desc = row.getAttribute('data-file-description') || '';
      const folder = row.getAttribute('data-file-folder') || '';
      const category = row.getAttribute('data-file-category') || '';
      const expires = row.getAttribute('data-file-expires') || '';

      editFileId.value = id;
      editFileName.textContent = '[' + id + '] ' + name;
      editDesc.value = desc;
      editFolder.value = folder;
      editCategory.value = category;
      editExpires.value = expires ? expires.slice(0, 10) : '';
      editModal.classList.remove('hidden');
    }

    function closeModal() {
      editModal.classList.add('hidden');
    }

    document.querySelectorAll('.file-edit-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const row = e.target.closest('tr');
        if (row) openModal(row);
      });
    });

    if (cancelBtn) {
      cancelBtn.addEventListener('click', (e) => {
        e.preventDefault();
        closeModal();
      });
    }
    if (backdrop) {
      backdrop.addEventListener('click', closeModal);
    }
  }


  // assign: sync selected file into hidden input
  window.assignSyncFileId = function(form) {
    var select = document.getElementById('assign-file-select');
    if (!select || !select.value) {
      alert('割り当てるファイルを選択してください');
      return false;
    }
    var hidden = form.querySelector('input[name="file_id"]');
    if (hidden) {
      hidden.value = select.value;
    }
    return true;
  };

})();
