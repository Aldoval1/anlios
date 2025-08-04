document.addEventListener('DOMContentLoaded', () => {
    // La función showToast se asume que existe globalmente desde toast.js
    
    const footerInputs = [
        document.getElementById('panel_footer_text'),
        document.getElementById('welcome_footer_text')
    ];

    footerInputs.forEach(input => {
        if (input) {
            input.addEventListener('input', () => {
                if (input.value.length > input.maxLength) {
                    // Trunca el texto para no exceder el límite visualmente
                    input.value = input.value.slice(0, input.maxLength);
                    
                    // Muestra la notificación de error
                    if (typeof showToast === 'function') {
                        showToast('error', `El pie de página no puede exceder los ${input.maxLength} caracteres.`, false, 5000);
                    }
                }
            });
        }
    });
});