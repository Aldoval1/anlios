function updatePreview() {
    // Helper function to set content and visibility
    const setElement = (element, content, property = 'textContent') => {
        const hasContent = content && content.trim() !== '';
        element.style.display = hasContent ? (property === 'src' ? 'block' : 'initial') : 'none';
        if (hasContent) {
            element[property] = content;
        }
    };

    // Helper function to update a full embed preview
    const updateEmbed = (prefix) => {
        const preview = document.getElementById(`${prefix}-preview`);
        
        // Color
        const color = document.getElementById(`${prefix}_color`).value;
        preview.style.borderColor = color;

        // Author
        const authorName = document.getElementById(`${prefix}_author_name`).value;
        const authorIcon = document.getElementById(`${prefix}_author_icon`).value;
        const authorContainer = preview.querySelector('.author');
        setElement(authorContainer, authorName || authorIcon, 'style.display');
        if (authorName || authorIcon) {
            authorContainer.style.display = 'flex';
            setElement(authorContainer.querySelector('.author-name'), authorName);
            setElement(authorContainer.querySelector('.author-icon'), authorIcon, 'src');
        }

        // Title
        let title = document.getElementById(`${prefix}_title`).value;
        if (prefix === 'welcome') {
            title = title.replace('{user}', 'UsuarioEjemplo');
        }
        setElement(preview.querySelector('.title'), title);

        // Description
        const description = document.getElementById(`${prefix}_description`).value;
        setElement(preview.querySelector('.description'), description);

        // Thumbnail
        const thumbnail = document.getElementById(`${prefix}_thumbnail`).value;
        setElement(preview.querySelector('.thumbnail'), thumbnail, 'src');
        
        // Main Image
        const image = document.getElementById(`${prefix}_image`).value;
        setElement(preview.querySelector('.main-image'), image, 'src');

        // Footer
        const footerText = document.getElementById(`${prefix}_footer_text`).value;
        const footerIcon = document.getElementById(`${prefix}_footer_icon`).value;
        const footerContainer = preview.querySelector('.footer');
        setElement(footerContainer, footerText || footerIcon, 'style.display');
        if (footerText || footerIcon) {
            footerContainer.style.display = 'flex';
            setElement(footerContainer.querySelector('.footer-text'), footerText);
            setElement(footerContainer.querySelector('.footer-icon'), footerIcon, 'src');
        }
    };

    updateEmbed('panel');
    updateEmbed('welcome');
}

// Llama a la función una vez al cargar la página para inicializar la vista previa
document.addEventListener('DOMContentLoaded', updatePreview);