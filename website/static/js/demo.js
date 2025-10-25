document.addEventListener('DOMContentLoaded', () => {
    // Elementos de la página
    const trigger = document.getElementById('demo-trigger');
    const landingPage = document.getElementById('landing-page');
    const demoPage = document.getElementById('demo-page');
    const exitDemoBtn = document.getElementById('exit-demo-btn');

    // Elementos de la animación
    const overlay = document.getElementById('animation-overlay');
    const animatedMustache = document.getElementById('animated-mustache');

    // Elementos del Chat
    const chatInput = document.getElementById('chat-input');
    const sendBtn = document.getElementById('send-chat-btn');
    const chatDisplay = document.getElementById('chat-display');

    // Elementos de Conocimiento
    const aiPromptInput = document.getElementById('demo-ai-prompt');
    const knowledgeBaseInput = document.getElementById('demo-knowledge-base');
    const knowledgeFeedback = document.getElementById('knowledge-feedback');
    const webForm = document.getElementById('demo-web-form');
    const youtubeForm = document.getElementById('demo-youtube-form');
    const pdfForm = document.getElementById('demo-pdf-form');

    // --- Lógica de Transición ---

    trigger.addEventListener('click', () => {
        const rect = trigger.getBoundingClientRect();

        animatedMustache.style.width = `${rect.width}px`;
        animatedMustache.style.height = `${rect.height}px`;
        animatedMustache.style.top = `${rect.top}px`;
        animatedMustache.style.left = `${rect.left}px`;
        animatedMustache.style.transform = 'scale(1)';
        animatedMustache.style.display = 'block';

        overlay.classList.add('visible');
        landingPage.classList.remove('active');

        setTimeout(() => {
            const scale = window.innerWidth / rect.width * 1.5;
            animatedMustache.style.transform = `scale(${scale})`;
        }, 50);

        setTimeout(() => {
            demoPage.classList.add('active');
            overlay.style.opacity = '0';

            // CHANGE: Show the new introductory toast
            if (!sessionStorage.getItem('demoWelcomed')) {
                showIntroductoryToast();
                sessionStorage.setItem('demoWelcomed', 'true');
            } else {
                // If already welcomed, just show the initial message directly
                showInitialChatMessage();
            }

        }, 600);

        setTimeout(() => {
            overlay.classList.remove('visible');
            overlay.style.opacity = '1';
            animatedMustache.style.display = 'none';
        }, 1100);
    });

    exitDemoBtn.addEventListener('click', () => {
        demoPage.classList.remove('active');
        resetDemo();
        setTimeout(() => {
            landingPage.classList.add('active');
        }, 500);
    });

    function resetDemo() {
        chatDisplay.innerHTML = '';
        aiPromptInput.value = `Eres Anlios, un asistente de IA amigable. Tu conocimiento se limita a la 'Base de Conocimientos'. Si no sabes la respuesta, dilo amablemente.\n\n--- BASE DE CONOCIMIENTOS ---\n{knowledge}`;
        knowledgeBaseInput.value = '';
        knowledgeFeedback.textContent = '';
        webForm.reset();
        youtubeForm.reset();
        pdfForm.reset();
        sessionStorage.removeItem('demoWelcomed');
    }

    // --- Lógica del Chat y Bienvenida de la Demo ---

    // CHANGE: New function for the animated welcome toast
    function showIntroductoryToast() {
        const toastContainer = document.getElementById('toast-container');
        const toastGif = document.getElementById('toast-gif');
        const toastMessage = document.getElementById('toast-message');
        const toastButtons = document.getElementById('toast-buttons');
        const progressBar = document.getElementById('toast-progress');

        const introDuration = 8000; // 8 seconds

        toastGif.src = '/static/images/hablando.gif';
        toastMessage.textContent = '¡Bienvenido a la demo! Aquí puedes probar mi IA. Define mi personalidad y conocimiento a la izquierda, y luego chatea conmigo a la derecha.';
        toastButtons.style.display = 'none';

        toastContainer.classList.add('show');

        progressBar.style.transition = 'none';
        progressBar.style.width = '100%';
        setTimeout(() => {
            progressBar.style.transition = `width ${introDuration / 1000}s linear`;
            progressBar.style.width = '0%';
        }, 50);

        setTimeout(() => {
            toastContainer.classList.remove('show');
            // Show the first chat message after the toast disappears
            showInitialChatMessage();
        }, introDuration);
    }

    function showInitialChatMessage() {
        const welcomeText = "¡Hola! Soy Anlios. ¡Estoy listo para que me pruebes!";
        appendMessage(welcomeText, 'Anlios Bot', '/static/images/favicon.png');
    }

    sendBtn.addEventListener('click', sendMessage);
    chatInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendMessage();
    });

    async function sendMessage() {
        const messageText = chatInput.value.trim();
        if (!messageText) return;

        appendMessage(messageText, 'Usuario', 'https://cdn.discordapp.com/embed/avatars/0.png'); // Generic user avatar
        chatInput.value = '';

        const typingIndicator = appendMessage('Anlios está escribiendo...', 'Anlios Bot', '/static/images/favicon.png', true);

        try {
            const response = await fetch('/demo_chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: messageText,
                    prompt: aiPromptInput.value,
                    knowledge: knowledgeBaseInput.value,
                }),
            });

            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const data = await response.json();

            // Update typing indicator with the actual response
            const textElement = typingIndicator.querySelector('.text');
            if (textElement) {
                textElement.textContent = data.reply;
            }
            typingIndicator.classList.remove('typing');

        } catch (error) {
            console.error('Error fetching chat response:', error);
            const textElement = typingIndicator.querySelector('.text');
            if (textElement) {
                textElement.textContent = 'Lo siento, hubo un error al conectar con mis circuitos.';
            }
        }
    }

    // CHANGE: Rewrote this function to correctly build the message HTML
    function appendMessage(text, username, avatarSrc, isTyping = false) {
        const messageDiv = document.createElement('div');
        messageDiv.className = 'discord-message';
        if (isTyping) {
            messageDiv.classList.add('typing');
        }

        messageDiv.innerHTML = `
            <img src="${avatarSrc}" alt="${username} avatar" class="discord-message-avatar">
            <div class="discord-message-content">
                <div class="username">${username}</div>
                <div class="text">${text}</div>
            </div>
        `;
        chatDisplay.appendChild(messageDiv);
        chatDisplay.scrollTop = chatDisplay.scrollHeight;
        return messageDiv;
    }

    // --- Lógica de Conocimiento de la Demo ---

    async function handleKnowledgeForm(event, sourceType) {
        event.preventDefault();
        const form = event.target;
        const submitButton = form.querySelector('button[type="submit"]');
        const originalButtonText = submitButton.textContent;

        submitButton.disabled = true;
        submitButton.textContent = '...';
        knowledgeFeedback.textContent = 'Extrayendo información...';
        knowledgeFeedback.style.color = '#ffb3b3';

        const formData = new FormData(form);
        formData.append('source_type', sourceType);

        try {
            const response = await fetch('/demo_extract_knowledge', { method: 'POST', body: formData });
            const data = await response.json();

            if (data.success) {
                knowledgeBaseInput.value += (knowledgeBaseInput.value ? '\n\n' : '') + data.text;
                knowledgeFeedback.textContent = '¡Información añadida!';
                knowledgeFeedback.style.color = '#28a745';
                form.reset();
            } else {
                throw new Error(data.error || 'Ocurrió un error desconocido.');
            }
        } catch (error) {
            knowledgeFeedback.textContent = `Error: ${error.message}`;
            knowledgeFeedback.style.color = '#dc3545';
        } finally {
            submitButton.disabled = false;
            submitButton.textContent = originalButtonText;
        }
    }

    webForm.addEventListener('submit', (e) => handleKnowledgeForm(e, 'web'));
    youtubeForm.addEventListener('submit', (e) => handleKnowledgeForm(e, 'youtube'));
    pdfForm.addEventListener('submit', (e) => handleKnowledgeForm(e, 'pdf'));
});