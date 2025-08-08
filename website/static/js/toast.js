document.addEventListener('DOMContentLoaded', () => {
    const toastContainer = document.getElementById('toast-container');
    const toastGif = document.getElementById('toast-gif');
    const toastMessage = document.getElementById('toast-message');
    const toastButtons = document.getElementById('toast-buttons');
    const confirmButton = document.getElementById('toast-confirm');
    const cancelButton = document.getElementById('toast-cancel');
    const progressBar = document.getElementById('toast-progress');

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

        progressBar.style.transition = 'none';
        progressBar.style.width = '100%';
        if (duration > 0) {
            setTimeout(() => {
                progressBar.style.transition = `width ${duration / 1000}s linear`;
                progressBar.style.width = '0%';
            }, 50);
            toastTimeout = setTimeout(hideToast, duration);
        } else {
             progressBar.style.width = '100%'; // No progress for sticky toasts
        }
    }

    function hideToast() {
        toastContainer.classList.remove('show');
    }

    // Expose showToast globally for simple notifications
    window.showToast = showToast;

    // CHANGE: New function for theme preview toast
    window.showThemeToast = function() {
        showToast('warning', 'Has previsualizado un nuevo tema. ¿Quieres guardarlo?', true, 0);

        // Clone buttons to remove old event listeners
        const newConfirm = confirmButton.cloneNode(true);
        confirmButton.parentNode.replaceChild(newConfirm, confirmButton);
        newConfirm.textContent = "Guardar Tema";

        const newCancel = cancelButton.cloneNode(true);
        cancelButton.parentNode.replaceChild(newCancel, cancelButton);
        newCancel.textContent = "Cancelar";

        newConfirm.addEventListener('click', () => {
            if (typeof window.savePreviewedTheme === 'function') {
                window.savePreviewedTheme();
                showToast('success', '¡Tema guardado con éxito!', false, 3000);
            }
        });

        newCancel.addEventListener('click', () => {
            if (typeof window.revertToSavedTheme === 'function') {
                window.revertToSavedTheme();
                hideToast();
            }
        });
    };
});