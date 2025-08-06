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
        
        // 1. Posicionar el bigote de la animación sobre el original
        animatedMustache.style.width = `${rect.width}px`;
        animatedMustache.style.height = `${rect.height}px`;
        animatedMustache.style.top = `${rect.top}px`;
        animatedMustache.style.left = `${rect.left}px`;
        animatedMustache.style.display = 'block';
        animatedMustache.style.transform = 'scale(1)';

        // 2. Mostrar la capa de superposición negra
        overlay.classList.add('visible');

        // 3. Animar el bigote y desvanecer la página de inicio
        setTimeout(() => {
            const scale = window.innerWidth / rect.width * 1.5;
            animatedMustache.style.transform = `scale(${scale})`;
            landingPage.classList.remove('active');
        }, 50); // Pequeño retraso para asegurar que las transiciones se apliquen

        // 4. Cuando la animación termina, mostrar la página de la demo
        setTimeout(() => {
            demoPage.classList.add('active');
            if (!sessionStorage.getItem('demoWelcomed')) {
                showWelcomeMessage();
                sessionStorage.setItem('demoWelcomed', 'true');
            }
        }, 600); // Duración de la animación del bigote + un poco más
    });

    exitDemoBtn.addEventListener('click', () => {
        // 1. Ocultar la demo y empezar a desvanecer la capa negra
        demoPage.classList.remove('active');
        overlay.style.opacity = '0';
        
        // 2. Limpiar todo
        resetDemo();
        
        // 3. Cuando la transición termina, ocultar la capa y el bigote animado
        setTimeout(() => {
            overlay.classList.remove('visible');
            overlay.style.opacity = '1'; // Reset para la próxima vez
            animatedMustache.style.display = 'none';
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

    // --- Lógica del Chat de la Demo ---

    function showWelcomeMessage() {
        const welcomeText = "¡Hola! Soy Anlios. En esta demo, puedes darme una personalidad y conocimientos a la izquierda. Luego, ¡puedes chatear conmigo aquí a la derecha para ver cómo respondo!";
        appendMessage(welcomeText, 'Anlios', '/static/images/hablando.gif');
    }

    sendBtn.addEventListener('click', sendMessage);
    chatInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendMessage();
    });

    async function sendMessage() {
        const messageText = chatInput.value.trim();
        if (!messageText) return;

        appendMessage(messageText, 'Usuario', '/static/images/favicon.png');
        chatInput.value = '';
        
        const typingIndicator = appendMessage('Anlios está escribiendo...', 'Anlios', '/static/images/favicon.png', true);

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
            
            typingIndicator.querySelector('.text').textContent = data.reply;
            typingIndicator.classList.remove('typing');

        } catch (error) {
            console.error('Error fetching chat response:', error);
            typingIndicator.querySelector('.text').textContent = 'Lo siento, hubo un error al conectar con mis circuitos.';
        }
    }

    function appendMessage(text, username, avatarSrc, isTyping = false) {
        const messageDiv = document.createElement('div');
        messageDiv.className = 'discord-message';
        if (isTyping) messageDiv.classList.add('typing');

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