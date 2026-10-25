/**
 * AntiPhish AI - Lógica del frontend (Vanilla JS ES6)
 */

const EXAMPLES = {
    'safe-email': Asunto: Confirmación de compra

Hola María,

Te confirmamos que tu compra número #8821 ha sido procesada correctamente.
El monto total es de \.000 y será entregado el próximo jueves.

Puedes ver el detalle de tu pedido en tu cuenta, iniciando sesión normalmente
en nuestra tienda online.

Gracias por confiar en nosotros.

--
Atención al Cliente
TiendaOnline,

    'phish-email': Asunto: URGENTE - Su cuenta ha sido bloqueada

Estimado cliente,

Hemos detectado actividad inusual en su cuenta bancaria. Por motivos de
seguridad, su acceso ha sido suspendido de manera temporal.

Para evitar el cierre permanente de su cuenta, debe verificar su identidad
en las próximas 24 horas haciendo clic aquí:

http://bit.ly/verifica-bbva-urgente

Si no actúa de inmediato, su cuenta será eliminada definitivamente.

Banco Nacional - Departamento de Seguridad,

    'safe-url': 'https://www.google.com/search?q=como+me+protejo+del+phishing',

    'phish-url': 'http://paypal-security-update.xyz/login/verificar-cuenta.php?user=12345'
};

let currentMode = 'email';
let gaugeColor = null;

function switchTab(mode) {
    currentMode = mode;
    const btnEmail = document.getElementById('tab-email');
    const btnUrl = document.getElementById('tab-url');
    const panelEmail = document.getElementById('panel-email');
    const panelUrl = document.getElementById('panel-url');

    if (mode === 'email') {
        btnEmail.className = 'tab-active px-6 py-4 text-sm font-medium flex items-center gap-2';
        btnUrl.className = 'px-6 py-4 text-sm font-medium text-slate-500 hover:text-slate-700 flex items-center gap-2 transition-colors';
        panelEmail.classList.remove('hidden');
        panelUrl.classList.add('hidden');
    } else {
        btnUrl.className = 'tab-active px-6 py-4 text-sm font-medium flex items-center gap-2';
        btnEmail.className = 'px-6 py-4 text-sm font-medium text-slate-500 hover:text-slate-700 flex items-center gap-2 transition-colors';
        panelUrl.classList.remove('hidden');
        panelEmail.classList.add('hidden');
    }
    document.getElementById('result-section').classList.add('hidden');
}

function loadExample(key) {
    const text = EXAMPLES[key];
    if (currentMode === 'email') {
        document.getElementById('email-input').value = text;
    } else {
        document.getElementById('url-input').value = text;
    }
}

async function analyze(mode) {
    const inputId = mode === 'email' ? 'email-input' : 'url-input';
    const inputEl = document.getElementById(inputId);
    const content = inputEl.value.trim();

    if (!content) {
        alert('Por favor, ingresa un texto o URL para analizar.');
        inputEl.focus();
        return;
    }

    const btn = event ? event.currentTarget : null;
    if (btn) {
        btn.innerHTML = '<svg class="w-5 h-5 text-white animate-spin" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg> Analizando...';
        btn.disabled = true;
    }

    try {
        const endpoint = mode === 'email' ? '/analyze/email' : '/analyze/url';
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content: content })
        });

        if (!response.ok) {
            throw new Error('Error del servidor: ' + response.status);
        }

        const data = await response.json();
        renderResult(mode, data);
    } catch (err) {
        alert('Error al analizar: ' + err.message);
    } finally {
        if (btn) {
            btn.innerHTML = mode === 'email'
                ? '<span>Analizar mensaje</span><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v4m0 0v4m0-4l4-4m-4 4l-4-4"></path></svg>'
                : '<span>Analizar enlace</span><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v4m0 0v4m0-4l4-4m-4 4l-4-4"></path></svg>';
            btn.disabled = false;
        }
    }
}

function renderResult(mode, data) {
    const section = document.getElementById('result-section');
    const scoreEl = document.getElementById('score-badge');
    const levelEl = document.getElementById('level-indicator');
    const typeEl = document.getElementById('result-type');
    const flagsEl = document.getElementById('flags-list');
    const recEl = document.getElementById('recommendation-text');
    const gaugeColorEl = document.getElementById('gauge-color');

    const score = data.risk_score;
    const level = data.level;

    typeEl.textContent = mode === 'email' ? 'Análisis de correo / mensaje de texto' : 'Análisis de URL / enlace web';

    scoreEl.textContent = score + '%';
    scoreEl.className = 'text-4xl font-bold ' + (score <= 30 ? 'text-green-600' : score <= 69 ? 'text-yellow-600' : 'text-red-600');

    let levelClass, levelBg;
    if (score <= 30) { levelClass = 'text-green-600'; levelBg = 'bg-green-100 border border-green-200'; }
    else if (score <= 69) { levelClass = 'text-yellow-600'; levelBg = 'bg-yellow-100 border border-yellow-200'; }
    else { levelClass = 'text-red-600'; levelBg = 'bg-red-100 border border-red-200 pulse-red'; }
    levelEl.className = 'px-4 py-2 rounded-full text-sm font-bold ' + levelClass + ' ' + levelBg;
    levelEl.textContent = level;

    const arcLength = 251;
    const offset = arcLength - (score / 100) * arcLength;
    if (gaugeColorEl) {
        gaugeColorEl.style.stroke = score <= 30 ? '#10b981' : score <= 69 ? '#eab308' : '#ef4444';
        gaugeColorEl.style.strokeDashoffset = offset;
    }

    const needle = document.getElementById('gauge-needle');
    if (needle) {
        const angle = 40 + (score / 100) * 100;
        needle.style.transform = 'rotate(' + angle + 'deg)';
    }

    flagsEl.innerHTML = '';
    if (data.flags && data.flags.length > 0) {
        data.flags.forEach(flag => {
            const div = document.createElement('div');
            div.className = 'flex items-start gap-2 p-2 bg-red-50 rounded border border-red-100 text-sm text-red-800';
            div.innerHTML = '<span class="flex-shrink-0 mt-1">!</span>' + escapeHtml(flag);
            flagsEl.appendChild(div);
        });
    } else {
        flagsEl.innerHTML = '<div class="p-2 bg-green-50 rounded border border-green-100 text-sm text-green-700">No se detectaron banderas de alerta.</div>';
    }

    recEl.textContent = data.recommendation || 'No hay recomendación disponible.';

    section.classList.remove('hidden');
    section.classList.add('fade-in');
    section.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

document.addEventListener('DOMContentLoaded', () => {
    const emailInput = document.getElementById('email-input');
    const urlInput = document.getElementById('url-input');

    emailInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
            e.preventDefault();
            analyze('email');
        }
    });

    urlInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            analyze('url');
        }
    });

    gaugeColor = document.getElementById('gauge-color');
});
