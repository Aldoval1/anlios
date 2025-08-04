document.addEventListener('DOMContentLoaded', () => {
    const toastContainer = document.getElementById('toast-container');
    const toastGif = document.getElementById('toast-gif');
    const toastMessage = document.getElementById('toast-message');
    const toastButtons = document.getElementById('toast-buttons');
    const confirmButton = document.getElementById('toast-confirm');
    const cancelButton = document.getElementById('toast-cancel');
    const progressBar = document.getElementById('toast-progress');

    let hasUnsavedChanges = false;
    let activeForm = null;
    let toastTimeout;

    const baseImagePath = '/static/images/';
    const gifs = {
        warning: baseImagePath + 'warning.gif',
        loading: baseImagePath + 'loading.gif',
        success: baseImagePath + 'success.gif',
        error: baseImagePath + 'error.gif'
    };

    function showToast(state, message, showButtons = false, duration = 5000) {
        clearTimeout(toastTimeout);

        toastGif.src = gifs[state];
        toastMessage.textContent = message;
        toastButtons.style.display = showButtons ? 'flex' : 'none';
        
        toastContainer.classList.add('show');

        // Animar la barra de progreso
        progressBar.style.transition = 'none';
        progressBar.style.width = '100%';
        setTimeout(() => {
            progressBar.style.transition = `width ${duration / 1000}s linear`;
            progressBar.style.width = '0%';
        }, 50);

        if (duration > 0) {
            toastTimeout = setTimeout(hideToast, duration);
        }
    }

    function hideToast() {
        toastContainer.classList.remove('show');
    }

    // 1. Detectar cambios sin guardar
    const allForms = document.querySelectorAll('form');
    allForms.forEach(form => {
        form.addEventListener('input', () => {
            if (!hasUnsavedChanges) {
                showToast('warning', 'Tienes cambios sin guardar.', true, 0); // No se oculta solo
                hasUnsavedChanges = true;
                activeForm = form; // Guardamos el formulario que tiene cambios
            }
        });

        form.addEventListener('submit', () => {
            showToast('loading', 'Guardando cambios...', false, 10000); // Larga duración por si tarda
            hasUnsavedChanges = false;
            activeForm = null;
        });
    });

    // 2. Lógica de los botones del toast
    confirmButton.addEventListener('click', () => {
        if (activeForm) {
            // Encuentra el botón de envío principal del formulario y haz clic en él
            const submitButton = activeForm.querySelector('button[type="submit"]');
            if (submitButton) {
                submitButton.click();
            }
        }
    });

    cancelButton.addEventListener('click', () => {
        if (activeForm) {
            activeForm.reset(); // Resetea los campos del formulario
            hasUnsavedChanges = false;
            activeForm = null;
            hideToast();
        }
    });

    // 3. Detectar estado desde la URL
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('save') === 'success') {
        showToast('success', '¡Cambios guardados con éxito!');
    } else if (urlParams.get('save') === 'error') {
        showToast('error', '¡Hubo un error al guardar!');
    }
});