document.addEventListener('DOMContentLoaded', () => {
    // Escuchar cambios en las pestañas para alternar la vista previa
    const embedTabs = document.querySelectorAll('#embedTabs button');
    embedTabs.forEach(tab => {
        tab.addEventListener('shown.bs.tab', event => {
            const targetId = event.target.getAttribute('data-bs-target');
            const panelPreview = document.getElementById('panel-preview');
            const welcomePreview = document.getElementById('welcome-preview');

            if (targetId === '#panel-editor') {
                panelPreview.style.display = 'block';
                welcomePreview.style.display = 'none';
            } else if (targetId === '#welcome-editor') {
                panelPreview.style.display = 'none';
                welcomePreview.style.display = 'block';
            }
            updatePreview();
        });
    });

    // Llamada inicial para asegurar que la vista previa esté correcta al cargar
    updatePreview();
});

function updatePreview() {
    const activeTab = document.querySelector('#embedTabs .nav-link.active');
    if (!activeTab) return;
    
    const prefix = activeTab.id.includes('panel') ? 'panel' : 'welcome';
    const preview = document.getElementById(`${prefix}-preview`);

    // --- Helper para establecer contenido y visibilidad ---
    const setElement = (element, content, property = 'textContent') => {
        if (!element) return;
        const hasContent = content && String(content).trim() !== '';
        // El contenedor del elemento (p.ej. el div del autor) se oculta si no hay contenido
        const parentContainer = element.parentElement;
        if (parentContainer && parentContainer.classList.contains('embed-author')) {
             const nameEl = parentContainer.querySelector('.embed-author-name');
             const iconEl = parentContainer.querySelector('.embed-author-icon');
             const hasName = nameEl ? nameEl.textContent.trim() !== '' : false;
             const hasIcon = iconEl ? iconEl.src.trim() !== '' && !iconEl.src.endsWith('/') : false;
             parentContainer.style.display = (hasName || hasIcon) ? 'flex' : 'none';
        } else if (parentContainer && parentContainer.classList.contains('embed-footer')) {
            const textEl = parentContainer.querySelector('.embed-footer-text');
            const iconEl = parentContainer.querySelector('.embed-footer-icon');
            const hasText = textEl ? textEl.textContent.trim() !== '' : false;
            const hasIcon = iconEl ? iconEl.src.trim() !== '' && !iconEl.src.endsWith('/') : false;
            parentContainer.style.display = (hasText || hasIcon) ? 'flex' : 'none';
        } else {
             element.style.display = hasContent ? 'block' : 'none';
        }
        
        if (hasContent) {
            if (property === 'src' && element.tagName === 'IMG') {
                element.src = content;
            } else {
                element[property] = content;
            }
        }
    };

    // --- Actualizar campos del embed ---
    const color = document.getElementById(`${prefix}_color`).value;
    preview.style.borderColor = color;

    setElement(preview.querySelector('.embed-author-name'), document.getElementById(`${prefix}_author_name`).value);
    setElement(preview.querySelector('.embed-author-icon'), document.getElementById(`${prefix}_author_icon`).value, 'src');

    let title = document.getElementById(`${prefix}_title`).value;
    if (prefix === 'welcome') {
        title = title.replace('{user}', 'UsuarioEjemplo');
    }
    setElement(preview.querySelector('.embed-title'), title);

    setElement(preview.querySelector('.embed-description'), document.getElementById(`${prefix}_description`).value);
    setElement(preview.querySelector('.embed-thumbnail'), document.getElementById(`${prefix}_thumbnail`).value, 'src');
    setElement(preview.querySelector('.embed-image'), document.getElementById(`${prefix}_image`).value, 'src');
    
    setElement(preview.querySelector('.embed-footer-text'), document.getElementById(`${prefix}_footer_text`).value);
    setElement(preview.querySelector('.embed-footer-icon'), document.getElementById(`${prefix}_footer_icon`).value, 'src');
}