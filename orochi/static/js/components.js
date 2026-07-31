class OrochiPlugin extends HTMLElement {
    set data(plugin) {
        this.innerHTML = `
        <li class="group mb-1">
            <label class="flex items-center py-1 px-2 rounded-lg hover:bg-zinc-100 dark:hover:bg-zinc-600 transition-colors cursor-pointer border border-transparent hover:border-zinc-400 dark:hover:border-zinc-500" data-plugin="${plugin.name}" title="${plugin.comment || ''}">
                <div class="relative flex items-center justify-center w-5 h-5 mr-3 shrink-0">
                    <input type="radio" id="plugin_radio_${plugin.name}" name="plugin_radio" class="peer sr-only" value="${plugin.name}">
                    <div class="w-4 h-4 border border-zinc-400 dark:border-zinc-500 rounded-full bg-white dark:bg-zinc-700 peer-checked:border-[5px] peer-checked:border-blue-500 transition-all shadow-inner"></div>
                </div>
                <span class="text-sm font-medium text-zinc-800 dark:text-zinc-200 group-hover:text-zinc-900 dark:hover:text-white transition-colors break-all cursor-pointer m-0">${plugin.name}</span>
            </label>
        </li>`;
    }
}
customElements.define('orochi-plugin', OrochiPlugin);

class OrochiDump extends HTMLElement {
    set data(dump) {
        const isReadOnly = dump.isReadOnly || false;

        let osIcon = '<i class="fas fa-robot"></i>';
        if (dump.operating_system === 'Linux') osIcon = '<i class="fab fa-linux"></i>';
        else if (dump.operating_system === 'Windows') osIcon = '<i class="fab fa-windows"></i>';
        else if (dump.operating_system === 'Mac') osIcon = '<i class="fab fa-apple"></i>';

        let statusBox = '';
        if (![2, 5, 6].includes(dump.status)) {
            statusBox = `
                <input type="checkbox" class="peer sr-only" id="checkbox_${dump.index}" />
                <div class="color_box w-5 h-5 border border-zinc-400 dark:border-zinc-500 rounded bg-zinc-50 border border-zinc-200 dark:bg-zinc-700 dark:border-zinc-600 peer-checked:bg-[var(--dump-color)] peer-checked:border-transparent transition-all shadow-inner" style="--dump-color: ${dump.color};"></div>
                <i class="fas fa-check absolute text-zinc-900 dark:text-white text-[10px] opacity-0 peer-checked:opacity-100 transition-opacity pointer-events-none drop-shadow-md"></i>`;
        } else {
            statusBox = `
                <input type="checkbox" disabled class="sr-only" id="checkbox_${dump.index}" />
                <div class="w-5 h-5 border border-zinc-300 dark:border-zinc-600 rounded bg-zinc-200 dark:bg-black opacity-50 shadow-inner"></div>`;
        }

        let actionButtons = `
            <li>
                <a href="#" class="block px-4 py-2 hover:bg-zinc-100 dark:hover:bg-zinc-600 hover:text-zinc-900 dark:hover:text-white transition-colors hex-index"
                   hx-get="/hex_view/${dump.index}"
                   hx-target="#modal-update .modal-content"
                   onclick="document.getElementById('modal-update').classList.remove('hidden'); document.getElementById('modal-update').classList.add('flex')">
                    <i class="fas fa-asterisk w-5"></i> Hex View
                </a>
            </li>
            <li>
                <a href="#" class="block px-4 py-2 hover:bg-zinc-100 dark:hover:bg-zinc-600 hover:text-zinc-900 dark:hover:text-white transition-colors" onclick="document.getElementById('modal-update').classList.remove('hidden'); document.getElementById('modal-update').classList.add('flex')" hx-get="/info?index=${dump.index}" hx-target="#modal-update .modal-content">
                    <i class="fas fa-info-circle w-5"></i> Info
                </a>
            </li>`;

        if (!isReadOnly) {
            actionButtons += `
                <li>
                    <a href="#" class="block px-4 py-2 hover:bg-zinc-100 dark:hover:bg-zinc-600 hover:text-zinc-900 dark:hover:text-white transition-colors" onclick="document.getElementById('modal-update').classList.remove('hidden'); document.getElementById('modal-update').classList.add('flex')" hx-get="/edit?index=${dump.index}" hx-target="#modal-update .modal-content">
                        <i class="fas fa-edit w-5"></i> Edit
                    </a>
                </li>
                <li>
                    <a href="#" class="block px-4 py-2 hover:bg-red-900/50 hover:text-red-400 transition-colors remove-index" data-index="${dump.index}">
                        <i class="fas fa-trash w-5"></i> Delete
                    </a>
                </li>`;

            if (dump.status === 6) {
                actionButtons += `
                    <li>
                        <a href="#" class="block px-4 py-2 hover:bg-zinc-100 dark:hover:bg-zinc-600 hover:text-zinc-900 dark:hover:text-white transition-colors" onclick="document.getElementById('modal-update').classList.remove('hidden'); document.getElementById('modal-update').classList.add('flex')" hx-get="/banner_symbols?index=${dump.index}" hx-target="#modal-update .modal-content">
                            <i class="fas fa-cloud-arrow-down w-5"></i> Download Symbols
                        </a>
                    </li>
                    <li>
                        <a href="#" class="block px-4 py-2 hover:bg-zinc-100 dark:hover:bg-zinc-600 hover:text-zinc-900 dark:hover:text-white transition-colors"
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
                            <i class="fas fa-arrows-rotate w-5"></i> Reload Symbols
                        </a>
                    </li>`;
            } else if (dump.status === 2) {
                actionButtons += `
                    <li>
                        <span class="block px-4 py-2 text-yellow-500">
                            <i class="fas fa-file-zipper animate-pulse w-5"></i> Unzipping...
                        </span>
                    </li>`;
            } else if (dump.status === 5) {
                actionButtons += `
                    <li>
                        <a href="#" class="block px-4 py-2 hover:bg-red-900/50 hover:text-red-400 transition-colors error-index btn-log" data-log="${dump.description}">
                            <i class="fas fa-skull w-5"></i> View Error
                        </a>
                    </li>`;
            } else {
                if (dump.has_auto) {
                    actionButtons += `
                        <li>
                            <a href="#" class="block px-4 py-2 hover:bg-zinc-100 dark:hover:bg-zinc-600 hover:text-zinc-900 dark:hover:text-white transition-colors"
                               hx-get="/restart?index=${dump.index}"
                               hx-target="#modal-update .modal-content"
                               onclick="document.getElementById('modal-update').classList.remove('hidden'); document.getElementById('modal-update').classList.add('flex')">
                                <i class="fas fa-backward w-5"></i> Restart Auto Plugin
                            </a>
                        </li>`;
                }
            }
        }

        actionButtons += `
            <li>
                <a href="#" class="block px-4 py-2 hover:bg-zinc-100 dark:hover:bg-zinc-600 hover:text-zinc-900 dark:hover:text-white transition-colors download_obj download-index" data-path="/media/${dump.index}/linux-sample-1.bin">
                    <i class="fas fa-file-download w-5"></i> Download Dump
                </a>
            </li>`;

        this.innerHTML = `
        <li class="group">
            <form action="#">
                <div class="dump_container flex items-center justify-between p-2 rounded-lg hover:bg-zinc-100 dark:hover:bg-zinc-600 transition-colors border border-transparent hover:border-zinc-400 dark:border-zinc-500 group w-full" data-index="${dump.index}" data-color="${dump.color}">
                    <label class="flex items-center flex-1 min-w-0 cursor-pointer m-0" for="checkbox_${dump.index}">
                        <div class="relative flex items-center justify-center w-5 h-5 mr-3 shrink-0">
                            ${statusBox}
                        </div>
                        <div class="flex items-center text-zinc-600 dark:text-zinc-300 mr-2 shrink-0">
                            ${osIcon}
                        </div>
                        <abbr title="${dump.name}" class="text-sm font-medium text-zinc-800 dark:text-zinc-200 group-hover:text-zinc-900 dark:hover:text-white transition-colors truncate no-underline block w-full max-w-[120px]">${dump.name}</abbr>
                    </label>
                    <div class="relative group/dropdown ml-2 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity" style="overflow: visible;">
                        <button type="button" class="text-zinc-600 dark:text-zinc-300 hover:text-zinc-900 dark:hover:text-white p-1 rounded transition-colors" data-toggle="tooltip" data-placement="top" title="Actions">
                            <i class="fas fa-ellipsis-v px-1"></i>
                        </button>
                        <div class="absolute right-0 mt-1 w-48 bg-zinc-50 border border-zinc-200 dark:bg-zinc-700 dark:border-zinc-600 border border-zinc-300 dark:border-zinc-600 rounded-lg shadow-xl opacity-0 invisible group-hover/dropdown:opacity-100 group-hover/dropdown:visible transition-all z-50">
                            <ul class="py-1 text-sm text-zinc-800 dark:text-zinc-200">
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
        <ul class="nav nav-pills flex-column mb-auto pb-3">
            <button class="flex items-center w-full text-left text-zinc-800 dark:text-zinc-200 hover:text-zinc-900 dark:hover:text-white border-b border-zinc-300 dark:border-zinc-600 py-2 mb-2 transition-colors" type="button" data-collapse-toggle="collapse_${folder.folder_name}" aria-expanded="false" aria-controls="collapse_${folder.folder_name}">
                <i class="fas fa-folder fa-lg" style="margin-right: 15px;"></i>${folder.folder_name}
            </button>
            <ul class="hidden ml-3 mt-1" id="collapse_${folder.folder_name}">
                <div id="folder_${folder.folder_name}">
                    <orochi-dump></orochi-dump>
                </div>
            </ul>
        </ul>`;

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
            bodyContent = `<div class="alert alert-danger m-4" role="alert">${errors}</div>`;
        } else {
            bodyContent = `<div class="js-received" style="width: 100%; height: 60vh;"></div>`;
        }

        this.innerHTML = `
        <div class="modal-header">
            <h5 class="modal-title">${title}</h5>
            <button type="button" class="btn-close" onclick="document.getElementById('modal-update').classList.add('hidden'); document.getElementById('modal-update').classList.remove('flex')" aria-label="Close"></button>
        </div>
        <div class="modal-body">
            ${bodyContent}
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="document.getElementById('modal-update').classList.add('hidden'); document.getElementById('modal-update').classList.remove('flex')">Close</button>
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
