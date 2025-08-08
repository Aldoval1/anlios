document.addEventListener('DOMContentLoaded', () => {
    const configForm = document.getElementById('main-config-form');
    if (!configForm) return;

    let hasUnsavedChanges = false;

    // Función para marcar que hay cambios
    const setUnsavedChanges = () => {
        if (!hasUnsavedChanges) {
            hasUnsavedChanges = true;
            
            // CORREGIDO: Llamamos a la función showToast existente para mostrar
            // la notificación de advertencia con su GIF correspondiente.
            if (typeof showToast === 'function') {
                showToast(
                    'warning', // Usa el estado 'warning' para mostrar el GIF correcto
                    'Tienes cambios sin guardar. Haz clic en "Guardar Toda la Configuración" para aplicarlos.',
                    false, // No mostrar botones de confirmar/cancelar
                    8000   // Duración del toast en ms
                );
            }
        }
    };

    // Escuchar cambios en todos los inputs, textareas y selects del formulario
    configForm.addEventListener('input', setUnsavedChanges);

    // Al hacer clic en el botón de guardar, reseteamos el estado
    const saveButton = configForm.querySelector('button[name="action"][value="save_all"]');
    if (saveButton) {
        saveButton.addEventListener('click', () => {
            hasUnsavedChanges = false;
        });
    }
    
    // Avisar al usuario si intenta salir de la página con cambios sin guardar
    window.addEventListener('beforeunload', (event) => {
        if (hasUnsavedChanges) {
            event.preventDefault();
            // La mayoría de los navegadores modernos ya no muestran un mensaje personalizado,
            // pero es necesario para activar el diálogo de confirmación.
            event.returnValue = '';
        }
    });
});