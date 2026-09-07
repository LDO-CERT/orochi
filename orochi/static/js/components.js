class OrochiPlugin extends HTMLElement {
    set data(plugin) {
        this.innerHTML = `
        <li class="group mb-1">
            <label class="flex items-center py-1.5 px-2.5 rounded-lg hover:bg-zinc-100 dark:hover:bg-zinc-700/60 transition-colors cursor-pointer border border-transparent hover:border-zinc-300 dark:hover:border-zinc-600" for="plugin_radio_${plugin.name}" data-plugin="${plugin.name}" title="${plugin.comment || ''}">
                <div class="relative flex items-center justify-center w-4 h-4 mr-2.5 shrink-0">
                    <input type="radio" id="plugin_radio_${plugin.name}" name="plugin_radio" class="peer sr-only" value="${plugin.name}">
                    <div class="w-4 h-4 border border-zinc-400 dark:border-zinc-500 rounded-full bg-white dark:bg-zinc-800 peer-checked:border-[5px] peer-checked:border-blue-600 transition-all shadow-inner"></div>
                </div>
                <span class="text-xs font-medium text-zinc-700 dark:text-zinc-200 group-hover:text-zinc-900 dark:group-hover:text-white transition-colors break-all cursor-pointer m-0">${plugin.name}</span>
            </label>
        </li>`;
    }
}
customElements.define('orochi-plugin', OrochiPlugin);

class OrochiDump extends HTMLElement {
    set data(dump) {
        const isReadOnly = dump.isReadOnly || false;

        let osIcon = '<i class="fas fa-robot text-zinc-400"></i>';
        if (dump.operating_system === 'Linux') osIcon = '<i class="fab fa-linux text-amber-500"></i>';
        else if (dump.operating_system === 'Windows') osIcon = '<i class="fab fa-windows text-blue-500"></i>';
        else if (dump.operating_system === 'Mac') osIcon = '<i class="fab fa-apple text-zinc-400"></i>';

        let statusBox = '';
        if (![2, 5, 6].includes(dump.status)) {
            statusBox = `
                <input type="checkbox" class="peer sr-only" id="checkbox_${dump.index}" />
                <div class="color_box flex items-center justify-center w-4 h-4 border-2 rounded transition-all shadow-sm" style="--dump-color: ${dump.color}; border-color: var(--dump-color);">
                    <i class="check_icon fas fa-check text-white text-[9px] opacity-0 transition-all pointer-events-none drop-shadow-sm"></i>
                </div>`;
        } else {
            statusBox = `
                <input type="checkbox" disabled class="sr-only" id="checkbox_${dump.index}" />
                <div class="w-4 h-4 border-2 rounded opacity-40 shadow-inner" style="border-color: ${dump.color}; background-color: transparent;"></div>`;
        }

        let actionButtons = `
            <li>
                <a href="#" class="flex items-center px-3 py-1.5 hover:bg-zinc-50 dark:hover:bg-zinc-700/60 hover:text-zinc-900 dark:hover:text-white transition-colors hex-index"
                   hx-get="/hex_view/${dump.index}"
                   hx-target="#modal-update .modal-content"
                   onclick="document.getElementById('modal-update').classList.remove('hidden'); document.getElementById('modal-update').classList.add('flex')">
                    <i class="fas fa-asterisk w-4 text-zinc-400 mr-2 text-xs"></i> Hex View
                </a>
            </li>
            <li>
                <a href="#" class="flex items-center px-3 py-1.5 hover:bg-zinc-50 dark:hover:bg-zinc-700/60 hover:text-zinc-900 dark:hover:text-white transition-colors" onclick="document.getElementById('modal-update').classList.remove('hidden'); document.getElementById('modal-update').classList.add('flex')" hx-get="/info?index=${dump.index}" hx-target="#modal-update .modal-content">
                    <i class="fas fa-circle-info w-4 text-blue-500 mr-2 text-xs"></i> Info
                </a>
            </li>`;

        if (!isReadOnly) {
            actionButtons += `
                <li>
                    <a href="#" class="flex items-center px-3 py-1.5 hover:bg-zinc-50 dark:hover:bg-zinc-700/60 hover:text-zinc-900 dark:hover:text-white transition-colors" onclick="document.getElementById('modal-update').classList.remove('hidden'); document.getElementById('modal-update').classList.add('flex')" hx-get="/edit?index=${dump.index}" hx-target="#modal-update .modal-content">
                        <i class="fas fa-pen w-4 text-amber-500 mr-2 text-xs"></i> Edit
                    </a>
                </li>
                <li>
                    <a href="#" class="flex items-center px-3 py-1.5 hover:bg-rose-50 dark:hover:bg-rose-950/30 text-rose-600 dark:text-rose-400 transition-colors remove-index" data-index="${dump.index}">
                        <i class="fas fa-trash w-4 text-rose-500 mr-2 text-xs"></i> Delete
                    </a>
                </li>`;

            if (dump.status === 6) {
                actionButtons += `
                    <li>
                        <a href="#" class="flex items-center px-3 py-1.5 hover:bg-zinc-50 dark:hover:bg-zinc-700/60 hover:text-zinc-900 dark:hover:text-white transition-colors" onclick="document.getElementById('modal-update').classList.remove('hidden'); document.getElementById('modal-update').classList.add('flex')" hx-get="/banner_symbols?index=${dump.index}" hx-target="#modal-update .modal-content">
                            <i class="fas fa-cloud-arrow-down w-4 text-blue-500 mr-2 text-xs"></i> Download Symbols
                        </a>
                    </li>
                    <li>
                        <a href="#" class="flex items-center px-3 py-1.5 hover:bg-zinc-50 dark:hover:bg-zinc-700/60 hover:text-zinc-900 dark:hover:text-white transition-colors"
                            hx-get="/api/dumps/${dump.index}/reload_symbols"
                            hx-confirm="Are you sure you want to reload symbols?"
                            hx-swap="none"
                            hx-on:htmx:after-request="
                              if(event.detail.successful) {
                                  toast({title: 'Operation successful!', content: JSON.parse(event.detail.xhr.response).message, type: 'success'});
                                  selectedPlugin = null;
                                  if (typeof updateSidebar === 'function') updateSidebar();
                              } else {
                                  toast({title: 'Operation error!', content: JSON.parse(event.detail.xhr.response).errors || 'Error reloading symbols.', type: 'error'});
                              }">
                            <i class="fas fa-arrows-rotate w-4 text-blue-500 mr-2 text-xs"></i> Reload Symbols
                        </a>
                    </li>`;
            } else if (dump.status === 2) {
                actionButtons += `
                    <li>
                        <span class="flex items-center px-3 py-1.5 text-amber-500 text-xs">
                            <i class="fas fa-file-zipper animate-pulse w-4 mr-2"></i> Unzipping...
                        </span>
                    </li>`;
            } else if (dump.status === 5) {
                actionButtons += `
                    <li>
                        <a href="#" class="flex items-center px-3 py-1.5 hover:bg-rose-50 dark:hover:bg-rose-950/30 text-rose-600 dark:text-rose-400 transition-colors error-index btn-log" data-log="${dump.description}">
                            <i class="fas fa-triangle-exclamation w-4 text-rose-500 mr-2 text-xs"></i> View Error
                        </a>
                    </li>`;
            }
            else if (dump.has_auto) {
                actionButtons += `
                    <li>
                        <a href="#" class="flex items-center px-3 py-1.5 hover:bg-zinc-50 dark:hover:bg-zinc-700/60 hover:text-zinc-900 dark:hover:text-white transition-colors"
                            hx-get="/restart?index=${dump.index}"
                            hx-target="#modal-update .modal-content"
                            onclick="document.getElementById('modal-update').classList.remove('hidden'); document.getElementById('modal-update').classList.add('flex')">
                            <i class="fas fa-rotate-left w-4 text-blue-500 mr-2 text-xs"></i> Restart Auto Plugin
                        </a>
                    </li>`;
            }
        }

        actionButtons += `
            <li>
                <a href="#" class="flex items-center px-3 py-1.5 hover:bg-zinc-50 dark:hover:bg-zinc-700/60 hover:text-zinc-900 dark:hover:text-white transition-colors download_obj download-index" data-path="/media/${dump.index}/linux-sample-1.bin">
                    <i class="fas fa-file-arrow-down w-4 text-zinc-400 mr-2 text-xs"></i> Download Dump
                </a>
            </li>`;

        this.innerHTML = `
        <li class="group">
            <form action="#">
                <div class="dump_container flex items-center justify-between py-1.5 px-2.5 rounded-lg hover:bg-zinc-100 dark:hover:bg-zinc-700/60 transition-colors border border-transparent hover:border-zinc-300 dark:hover:border-zinc-600 group w-full" data-index="${dump.index}" data-color="${dump.color}" style="--dump-color: ${dump.color};">
                    <label class="flex items-center flex-1 min-w-0 cursor-pointer m-0" for="checkbox_${dump.index}">
                        <div class="relative flex items-center justify-center w-4 h-4 mr-2.5 shrink-0">
                            ${statusBox}
                        </div>
                        <div class="flex items-center text-xs mr-2 shrink-0">
                            ${osIcon}
                        </div>
                        <abbr title="${dump.name}" class="dump_title text-xs font-medium text-zinc-700 dark:text-zinc-200 group-hover:text-zinc-900 dark:group-hover:text-white transition-colors truncate no-underline block w-full max-w-[140px]">${dump.name}</abbr>
                    </label>
                    <div class="relative group/dropdown ml-1.5 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity" style="overflow: visible;">
                        <button type="button" class="text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 p-1 rounded transition-colors" data-toggle="tooltip" data-placement="top" title="Actions">
                            <i class="fas fa-ellipsis-vertical px-1 text-xs"></i>
                        </button>
                        <div class="absolute right-0 mt-1 w-48 bg-white dark:bg-zinc-800 border border-zinc-200 dark:border-zinc-700 rounded-xl shadow-xl opacity-0 invisible group-hover/dropdown:opacity-100 group-hover/dropdown:visible transition-all z-50">
                            <ul class="py-1 text-xs text-zinc-700 dark:text-zinc-200">
                                ${actionButtons}
                            </ul>
                        </div>
                    </div>
                </div>
            </form>
        </li>`;
    }
}
customElements.define('orochi-dump', OrochiDump);

class OrochiDumpFolder extends HTMLElement {
    set data(folder) {
        this.innerHTML = `
        <div class="mb-2">
            <button class="flex items-center w-full text-left text-xs font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400 hover:text-zinc-800 dark:hover:text-zinc-200 py-1.5 px-2 rounded-lg hover:bg-zinc-100 dark:hover:bg-zinc-700/60 transition-colors" type="button" data-collapse-toggle="collapse_${folder.folder_name}" aria-expanded="false" aria-controls="collapse_${folder.folder_name}">
                <i class="fas fa-folder mr-2 text-amber-500"></i>${folder.folder_name}
            </button>
            <ul class="hidden ml-2 pl-2 border-l border-zinc-200 dark:border-zinc-700 mt-1 space-y-1" id="collapse_${folder.folder_name}">
                <div id="folder_${folder.folder_name}">
                    <orochi-dump></orochi-dump>
                </div>
            </ul>
        </div>`;

        // Pass the dump data to the inner orochi-dump component
        const dumpEl = this.querySelector('orochi-dump');
        dumpEl.data = folder;
    }
}
customElements.define('orochi-dump-folder', OrochiDumpFolder);

class OrochiJsonModal extends HTMLElement {
    set data(opts) {
        const title = opts.title || 'JSON Report';
        const errors = opts.data && opts.data.errors;
        const jsonData = opts.data;

        let bodyContent = '';
        if (errors) {
            bodyContent = `<div class="p-4 text-sm rounded-xl bg-rose-50 text-rose-700 dark:bg-rose-950/30 dark:text-rose-300 border border-rose-200 dark:border-rose-900/50 m-4" role="alert">${errors}</div>`;
        } else {
            bodyContent = `<div class="js-received" style="width: 100%; height: 60vh;"></div>`;
        }

        this.innerHTML = `
        <div class="flex items-center justify-between p-4 md:p-5 border-b border-zinc-200 dark:border-zinc-700 rounded-t">
            <h5 class="text-lg font-bold text-zinc-900 dark:text-white flex items-center gap-2">
                <i class="fas fa-code text-blue-500"></i> ${title}
            </h5>
            <button type="button" class="text-zinc-400 hover:bg-zinc-100 dark:hover:bg-zinc-700 hover:text-zinc-900 dark:hover:text-white rounded-lg text-sm w-8 h-8 inline-flex items-center justify-center transition-colors cursor-pointer" onclick="document.getElementById('modal-update').classList.add('hidden'); document.getElementById('modal-update').classList.remove('flex')" aria-label="Close">
                <svg class="w-3 h-3" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 14 14">
                    <path stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="m1 1 6 6m0 0 6 6M7 7l6-6M7 7l-6 6"/>
                </svg>
            </button>
        </div>
        <div class="p-4 md:p-5">
            ${bodyContent}
        </div>
        <div class="flex items-center justify-end p-4 md:p-5 border-t border-zinc-200 dark:border-zinc-700 rounded-b">
            <button type="button" class="px-4 py-2 text-sm font-medium text-zinc-700 dark:text-zinc-200 bg-zinc-100 dark:bg-zinc-700 hover:bg-zinc-200 dark:hover:bg-zinc-600 rounded-lg transition-colors cursor-pointer" onclick="document.getElementById('modal-update').classList.add('hidden'); document.getElementById('modal-update').classList.remove('flex')">Close</button>
        </div>`;

        if (!errors) {
            const container = this.querySelector('.js-received');
            const editorOptions = {
                mode: 'code',
                modes: ['text', 'code', 'view'],
                onEditable: function (node) {
                    if (!node.path) { return false; }
                }
            };
            const jsonEditor = new JSONEditor(container, editorOptions);
            jsonEditor.set(jsonData);
        }
    }
}
customElements.define('orochi-json-modal', OrochiJsonModal);


/* ==========================================================================
   Autocomplete & Folder Utilities
   ========================================================================== */

function getCsrfToken() {
    const input = document.querySelector('input[name="csrfmiddlewaretoken"]');
    if (input && input.value) return input.value;
    const cookie = document.cookie.split('; ').find(row => row.startsWith('csrftoken='));
    return cookie ? cookie.split('=')[1] : '';
}
window.getCsrfToken = getCsrfToken;

// Ensures a folder is created in the database before dump creation/editing
async function ensureFolderCreated(folderName) {
    if (!folderName || typeof folderName !== 'string' || !folderName.trim()) {
        return null;
    }
    const name = folderName.trim();
    const token = getCsrfToken();
    try {
        const res = await fetch('/api/folders/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': token
            },
            body: JSON.stringify({ name: name })
        });
        if (res.status === 201 || res.status === 200 || res.status === 400) {
            if (window.knownFolders) {
                window.knownFolders.add(name);
            }
            return name;
        }
    } catch (err) {
        console.warn('Error ensuring folder created:', err);
    }
    return name;
}
window.ensureFolderCreated = ensureFolderCreated;

// Generic autocomplete for datalists (e.g. hosts)
function setupAutocomplete(inputId, datalistId) {
    const input = document.getElementById(inputId);
    const datalist = document.getElementById(datalistId);
    if (!input || !datalist) return;
    if (input.dataset.autocompleteInit) return;
    input.dataset.autocompleteInit = 'true';

    const wrapper = document.createElement('div');
    wrapper.className = 'relative w-full';
    input.parentNode.insertBefore(wrapper, input);
    wrapper.appendChild(input);

    const dropdown = document.createElement('ul');
    dropdown.className = 'absolute z-50 w-full bg-white dark:bg-zinc-800 border border-zinc-200 dark:border-zinc-700 rounded-xl shadow-xl mt-1 hidden max-h-48 overflow-y-auto text-xs py-1 divide-y divide-zinc-100 dark:divide-zinc-700/60';
    wrapper.appendChild(dropdown);

    const options = Array.from(datalist.options).map(opt => opt.value);

    function showDropdown() {
        dropdown.innerHTML = '';
        const val = input.value.toLowerCase().trim();
        const filtered = options.filter(opt => opt.toLowerCase().includes(val));

        if (filtered.length === 0) {
            dropdown.classList.add('hidden');
            return;
        }

        filtered.forEach(opt => {
            const li = document.createElement('li');
            li.className = 'px-3.5 py-2 hover:bg-zinc-100 dark:hover:bg-zinc-700/70 cursor-pointer text-zinc-900 dark:text-zinc-100 transition-colors flex items-center justify-between';
            li.innerHTML = `<span>${opt}</span><span class="text-[10px] text-zinc-400">Select</span>`;
            li.onmousedown = (e) => {
                e.preventDefault();
                input.value = opt;
                dropdown.classList.add('hidden');
            };
            dropdown.appendChild(li);
        });
        dropdown.classList.remove('hidden');
    }

    input.addEventListener('focus', showDropdown);
    input.addEventListener('input', showDropdown);
    input.addEventListener('blur', () => dropdown.classList.add('hidden'));
    input.removeAttribute('list');
}
window.setupAutocomplete = setupAutocomplete;

// Rich folder autocomplete with existing folder picker & new folder creator
function setupFolderAutocomplete(inputId, datalistId) {
    const input = document.getElementById(inputId);
    const datalist = document.getElementById(datalistId);
    if (!input) return;
    if (input.dataset.folderAutocompleteInit) return;
    input.dataset.folderAutocompleteInit = 'true';

    const wrapper = document.createElement('div');
    wrapper.className = 'relative w-full';
    input.parentNode.insertBefore(wrapper, input);
    wrapper.appendChild(input);

    // Feedback badge container below input
    const badge = document.createElement('div');
    badge.className = 'mt-1.5 hidden items-center gap-1.5 text-xs transition-all';
    wrapper.parentNode.insertBefore(badge, wrapper.nextSibling);

    const dropdown = document.createElement('ul');
    dropdown.className = 'absolute z-50 w-full bg-white dark:bg-zinc-800 border border-zinc-200 dark:border-zinc-700 rounded-xl shadow-xl mt-1 hidden max-h-56 overflow-y-auto text-xs py-1 divide-y divide-zinc-100 dark:divide-zinc-700/60';
    wrapper.appendChild(dropdown);

    const knownFolders = new Set();
    if (datalist) {
        Array.from(datalist.options).forEach(opt => {
            if (opt.value && opt.value.trim()) knownFolders.add(opt.value.trim());
        });
    }

    window.knownFolders = window.knownFolders || new Set();
    knownFolders.forEach(f => window.knownFolders.add(f));

    // Refresh folders from /api/folders/ in background
    fetch('/api/folders/')
        .then(res => res.ok ? res.json() : [])
        .then(folders => {
            if (Array.isArray(folders)) {
                folders.forEach(f => {
                    const name = typeof f === 'string' ? f : (f.name || '');
                    if (name.trim()) {
                        knownFolders.add(name.trim());
                        window.knownFolders.add(name.trim());
                    }
                });
            }
        })
        .catch(() => {});

    let activeIndex = -1;

    function showFeedback(text, isError = false) {
        badge.className = `mt-1.5 flex items-center gap-1.5 text-xs ${isError ? 'text-rose-500' : 'text-emerald-600 dark:text-emerald-400 font-medium'}`;
        badge.innerHTML = isError
            ? `<i class="fas fa-exclamation-circle"></i> <span>${text}</span>`
            : `<i class="fas fa-check-circle text-emerald-500"></i> <span>${text}</span>`;
        setTimeout(() => {
            badge.className = 'mt-1.5 hidden items-center gap-1.5 text-xs transition-all';
        }, 3500);
    }

    async function selectAndCreateFolder(name, isNew) {
        input.value = name;
        dropdown.classList.add('hidden');

        if (isNew) {
            badge.className = 'mt-1.5 flex items-center gap-1.5 text-xs text-blue-600 dark:text-blue-400 font-medium';
            badge.innerHTML = `<svg class="animate-spin h-3.5 w-3.5" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path></svg> <span>Creating folder "${name}"...</span>`;

            await ensureFolderCreated(name);
            knownFolders.add(name);
            if (window.knownFolders) window.knownFolders.add(name);
            showFeedback(`Folder "${name}" created`);
        }
    }

    function renderDropdown() {
        dropdown.innerHTML = '';
        activeIndex = -1;
        const rawVal = input.value.trim();
        const lowerVal = rawVal.toLowerCase();

        const optionsArray = Array.from(knownFolders).sort((a, b) => a.localeCompare(b));
        const matching = optionsArray.filter(opt => opt.toLowerCase().includes(lowerVal));
        const exactMatch = optionsArray.some(opt => opt.toLowerCase() === lowerVal);

        if (optionsArray.length > 0 && matching.length > 0) {
            const header = document.createElement('li');
            header.className = 'px-3 py-1 text-[10px] font-bold uppercase tracking-wider text-zinc-400 dark:text-zinc-500 bg-zinc-50/80 dark:bg-zinc-800/80 sticky top-0 flex items-center justify-between';
            header.innerHTML = `<span><i class="fas fa-folder mr-1 text-amber-500"></i> Pick Existing Folder</span><span class="text-[10px] font-normal">${matching.length} available</span>`;
            dropdown.appendChild(header);
        }

        matching.forEach(opt => {
            const li = document.createElement('li');
            li.className = 'folder-opt-item px-3.5 py-2 hover:bg-zinc-100 dark:hover:bg-zinc-700/70 cursor-pointer text-zinc-900 dark:text-zinc-100 transition-colors flex items-center justify-between group';

            let labelHtml = opt;
            if (lowerVal) {
                const matchIdx = opt.toLowerCase().indexOf(lowerVal);
                if (matchIdx !== -1) {
                    labelHtml = opt.substring(0, matchIdx) +
                        '<strong class="text-blue-600 dark:text-blue-400 underline font-semibold">' +
                        opt.substring(matchIdx, matchIdx + lowerVal.length) +
                        '</strong>' +
                        opt.substring(matchIdx + lowerVal.length);
                }
            }

            li.innerHTML = `
                <span class="flex items-center gap-2">
                    <i class="fas fa-folder text-amber-500 text-xs"></i>
                    <span>${labelHtml}</span>
                </span>
                <span class="text-[10px] text-zinc-400 opacity-0 group-hover:opacity-100 transition-opacity">Select</span>
            `;

            li.onmousedown = (e) => {
                e.preventDefault();
                selectAndCreateFolder(opt, false);
            };
            dropdown.appendChild(li);
        });

        // Show "Create folder" option if user typed something that doesn't match an existing folder exactly
        if (rawVal && !exactMatch) {
            const createLi = document.createElement('li');
            createLi.className = 'create-folder-item px-3.5 py-2.5 bg-blue-50/70 dark:bg-blue-950/40 hover:bg-blue-100 dark:hover:bg-blue-900/60 text-blue-600 dark:text-blue-400 cursor-pointer transition-colors flex items-center justify-between font-medium';
            createLi.innerHTML = `
                <span class="flex items-center gap-2">
                    <i class="fas fa-folder-plus text-blue-500 text-sm"></i>
                    <span>Create folder "<strong>${rawVal}</strong>"</span>
                </span>
                <span class="text-[10px] font-bold uppercase tracking-wider bg-blue-100 dark:bg-blue-800 text-blue-700 dark:text-blue-200 px-2 py-0.5 rounded-full shadow-2xs">New Folder</span>
            `;
            createLi.onmousedown = async (e) => {
                e.preventDefault();
                await selectAndCreateFolder(rawVal, true);
            };
            dropdown.appendChild(createLi);
        }

        if (dropdown.children.length === 0) {
            dropdown.classList.add('hidden');
        } else {
            dropdown.classList.remove('hidden');
        }
    }

    input.addEventListener('focus', renderDropdown);
    input.addEventListener('input', renderDropdown);

    // Keyboard navigation
    input.addEventListener('keydown', (e) => {
        const items = dropdown.querySelectorAll('li:not(.sticky)');
        if (dropdown.classList.contains('hidden') || items.length === 0) {
            if (e.key === 'ArrowDown') {
                renderDropdown();
            }
            return;
        }

        if (e.key === 'ArrowDown') {
            e.preventDefault();
            activeIndex = (activeIndex + 1) % items.length;
            updateHighlight(items);
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            activeIndex = (activeIndex - 1 + items.length) % items.length;
            updateHighlight(items);
        } else if (e.key === 'Enter') {
            if (activeIndex >= 0 && activeIndex < items.length) {
                e.preventDefault();
                items[activeIndex].dispatchEvent(new MouseEvent('mousedown'));
            }
        } else if (e.key === 'Escape') {
            dropdown.classList.add('hidden');
        }
    });

    function updateHighlight(items) {
        items.forEach((item, idx) => {
            if (idx === activeIndex) {
                item.classList.add('bg-zinc-100', 'dark:bg-zinc-700/80');
                item.scrollIntoView({ block: 'nearest' });
            } else {
                item.classList.remove('bg-zinc-100', 'dark:bg-zinc-700/80');
            }
        });
    }

    document.addEventListener('click', (e) => {
        if (!wrapper.contains(e.target)) {
            dropdown.classList.add('hidden');
        }
    });

    input.removeAttribute('list');
}
window.setupFolderAutocomplete = setupFolderAutocomplete;
