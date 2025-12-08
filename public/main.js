const form = document.getElementById('domain-form');
const input = document.getElementById('domain-input');
const localInput = document.getElementById('local-part');
const honeypot = document.getElementById('hp-field');
const localError = document.getElementById('local-error');
const emailPreview = document.getElementById('email-preview');
const statusArea = document.getElementById('status-area');
const resultsSection = document.getElementById('results');
const resultMessage = document.getElementById('result-message');
const alternativesContainer = document.getElementById('alternatives');
const checkButton = document.getElementById('check-button');
const chosenDomainInput = document.getElementById('chosenDomain');
const existingDomainRadios = document.querySelectorAll('input[name="hasExistingDomain"]');
const existingDomainInfo = document.getElementById('existingDomainInfo');
const confirmationSection = document.getElementById('confirmation');
const selectionPreview = document.getElementById('selection-preview');
const selectionError = document.getElementById('selection-error');
const confirmSelectionButton = document.getElementById('confirm-selection');
const sessionInput = document.getElementById('sessionId');
const domainUnavailable = document.getElementById('domain-unavailable');

const apiBase =
  window.location.origin.startsWith('file://') || window.location.protocol === 'file:'
    ? 'http://localhost:3000'
    : '';

let currentDomain = 'votre-domaine.fr';
let pendingDomain = '';
let confirmedDomain = '';
let isSubmitting = false;
const localRegex = /^[a-z0-9-]{1,40}$/;
const urlParams = new URLSearchParams(window.location.search);
const sessionIdParam = urlParams.get('session_id') || urlParams.get('token') || '';
const emailParam = (urlParams.get('email') || '').trim().toLowerCase();
const appConfig = window.APP_CONFIG || {};
const disableCompletionGuard = Boolean(appConfig.disableCompletionGuard);
const hasAccessContext = Boolean(sessionIdParam || emailParam);

if (!hasAccessContext && !disableCompletionGuard) {
  window.location.href = '/acces-non-valide';
}

function setStatus(message, type = '') {
  statusArea.textContent = message || '';
  statusArea.className = `status ${type}`;
}

function clearResults() {
  resultsSection.classList.add('hidden');
  resultMessage.innerHTML = '';
  alternativesContainer.innerHTML = '';
  if (domainUnavailable) {
    domainUnavailable.textContent = '';
    domainUnavailable.style.display = 'none';
  }
}

function resetSelectionState() {
  pendingDomain = '';
  confirmedDomain = '';
  if (chosenDomainInput) chosenDomainInput.value = '';
  if (selectionPreview) selectionPreview.textContent = '';
  if (selectionError) selectionError.textContent = '';
  if (confirmationSection) confirmationSection.classList.add('hidden');
  if (confirmSelectionButton) confirmSelectionButton.disabled = true;
}

function showLocalError(message) {
  localError.textContent = message || '';
}

function validateLocalInput(showMessage = false) {
  const value = localInput.value.trim().toLowerCase();
  localInput.value = value;

  if (!value) {
    if (showMessage) showLocalError('Indiquez le début de votre adresse mail.');
    return false;
  }

  if (value.length > 40) {
    if (showMessage) {
      showLocalError(
        'Maximum 40 caractères. Utilisez uniquement lettres, chiffres ou tirets (sans accents : é, è, ê, ë, à, â, ä, ù, ü, û, ô, ö, î, ï, ç).'
      );
    }
    return false;
  }

  if (!localRegex.test(value)) {
    if (showMessage) {
      showLocalError(
        'Début d’adresse invalide. Lettres, chiffres ou tirets uniquement. Pas d’accents (é, è, ê, ë, à, â, ä, ù, ü, û, ô, ö, î, ï, ç).'
      );
    }
    return false;
  }

  if (showMessage) showLocalError('');
  return true;
}

function updateSelectionPreviewText() {
  if (!pendingDomain && !confirmedDomain) {
    if (selectionPreview) selectionPreview.textContent = '';
    return;
  }
  const domain = confirmedDomain || pendingDomain;
  const localPart = localInput.value || 'contact';
  if (selectionPreview) selectionPreview.textContent = `${localPart}@${domain}`;
}

function updatePreview(showMessage = false) {
  validateLocalInput(showMessage);
  const localPart = localInput.value || 'contact';
  const domainPart = input.value.trim() || currentDomain;
  emailPreview.textContent = `Adresse finale : ${localPart}@${domainPart}`;
  updateSelectionPreviewText();
}

function onDomainSelected(domain) {
  resetSelectionState();
  pendingDomain = domain;
  updateSelectionPreviewText();
  if (confirmationSection) confirmationSection.classList.remove('hidden');
  if (confirmSelectionButton) confirmSelectionButton.disabled = false;
  setStatus('Adresse proposée trouvée. Confirmez votre adresse email ci-dessous.', 'notice');
}

function renderChip(domain, primary = false) {
  const chip = document.createElement('button');
  chip.className = primary ? 'chip primary' : 'chip';
  chip.type = 'button';
  chip.textContent = domain;
  chip.addEventListener('click', (event) => {
    event.preventDefault();
    onDomainSelected(domain);
  });
  return chip;
}

function renderResults(data) {
  resultsSection.classList.remove('hidden');
  alternativesContainer.innerHTML = '';
  currentDomain = data.domain || currentDomain;
  updatePreview();
  resetSelectionState();

  if (data.available) {
    if (domainUnavailable) {
      domainUnavailable.textContent = '';
      domainUnavailable.style.display = 'none';
    }
    resultMessage.innerHTML = `<strong>${data.domain}</strong> est disponible. Cliquez ci-dessous pour le sélectionner.`;
    alternativesContainer.appendChild(renderChip(data.domain, true));
    return;
  }

  if (domainUnavailable) {
    domainUnavailable.textContent =
      `${data.domain} n’est pas disponible. Choisissez parmi les variantes proposées ci-dessous.`;
    domainUnavailable.style.display = 'block';
  }
  resultMessage.innerHTML =
    `<strong>${data.domain}</strong> n’est pas disponible. Cliquez sur une alternative ci-dessous pour la choisir, ou essayez une autre orthographe ou variante (ex : ajouter un autre mot, un tiret, une lettre, un chiffre, ou une autre terminaison comme .fr ou .com).`;

  if (!data.alternatives?.length) {
    const empty = document.createElement('div');
    empty.className = 'notice';
    empty.textContent =
      'Aucune alternative trouvée. Merci d’essayer une autre orthographe ou une variante (par exemple : ajouter un autre mot, un tiret, une lettre, un chiffre, ou une autre terminaison comme .com ou .fr).';
    alternativesContainer.appendChild(empty);
    return;
  }

  data.alternatives.forEach((alt) => {
    alternativesContainer.appendChild(renderChip(alt.domain));
  });
}

async function handleDomainCheck() {
  const domain = input.value.trim();
  const hpValue = honeypot.value.trim();
  if (isSubmitting) return;
  if (!validateLocalInput(true)) {
    setStatus(
      'Début d’adresse invalide. 1 à 40 caractères, uniquement lettres, chiffres ou tirets, sans accents (é, è, ê, ë, à, â, ä, ù, ü, û, ô, ö, î, ï, ç).',
      'error'
    );
    return;
  }
  if (hpValue) {
    setStatus('Requête bloquée.', 'error');
    return;
  }
  if (!domain) return;

  clearResults();
  resetSelectionState();
  setStatus('Vérification en cours...', 'notice');
  checkButton.disabled = true;

  try {
    const response = await fetch(`${apiBase}/api/check?domain=${encodeURIComponent(domain)}`);
    const payload = await response.json();

    if (!response.ok) {
      throw new Error(payload.error || 'Impossible de vérifier le domaine.');
    }

    setStatus('');
    renderResults(payload);
  } catch (error) {
    const friendly =
      error.message === 'Failed to fetch'
        ? 'Impossible de contacter le serveur. Vérifie que "npm start" tourne toujours.'
        : error.message?.toLowerCase().includes('nom de domaine invalide')
        ? 'Nom de domaine invalide.\nVérifiez qu’il contient une terminaison comme .fr ou .com et qu’il utilise uniquement des lettres, chiffres ou tirets.\nPas d’espaces, pas d’accents (é, è, ê, ë, à, â, ä, ù, ü, û, ô, ö, î, ï, ç), pas de caractères spéciaux (!, ?, %, &, /, _).'
        : error.message;
    setStatus(friendly || 'Impossible de vérifier le domaine.', 'error');
  } finally {
    checkButton.disabled = false;
  }
}

async function submitSelection() {
  const hpValue = honeypot.value.trim();
  const hasExistingDomain =
    Array.from(existingDomainRadios || []).find((r) => r.checked)?.value || '';
  if (isSubmitting) return;
  const payload = {
    fullName: (form.fullName?.value || '').trim(),
    company: (form.company?.value || '').trim(),
    currentEmail: (form.currentEmail?.value || '').trim(),
    hasExistingDomain,
    requestedDomain: (input.value || '').trim().toLowerCase(),
    chosenDomain: (chosenDomainInput?.value || '').trim().toLowerCase(),
    localPart: (localInput.value || '').trim().toLowerCase(),
    displayName: (form.displayName?.value || '').trim(),
    comment: '',
    honeypot: hpValue,
    sessionId: sessionIdParam || (sessionInput?.value || '').trim(),
  };

  if (!validateLocalInput(true)) {
    setStatus(
      'Début d’adresse invalide. 1 à 40 caractères, uniquement lettres, chiffres ou tirets, sans accents (é, è, ê, ë, à, â, ä, ù, ü, û, ô, ö, î, ï, ç).',
      'error'
    );
    return;
  }
  if (hpValue) {
    setStatus('Requête bloquée.', 'error');
    return;
  }
  if (!payload.requestedDomain) {
    setStatus('Indiquez un nom de domaine à vérifier.', 'error');
    return;
  }
  if (!payload.chosenDomain) {
    if (selectionError) {
      selectionError.textContent = 'Choisissez et confirmez un domaine dans la liste ci-dessus.';
    }
    setStatus('Confirmez le domaine avant de valider.', 'error');
    return;
  }

  try {
    setStatus('Envoi en cours...', 'notice');
    isSubmitting = true;
    if (confirmSelectionButton) {
      confirmSelectionButton.disabled = true;
      confirmSelectionButton.textContent = 'Envoi en cours...';
    }
    const response = await fetch(`${apiBase}/api/selection`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(body.error || 'Enregistrement impossible.');
    }

    window.location.href = '/merci';
  } catch (error) {
    setStatus(error.message || 'Une erreur est survenue.', 'error');
  } finally {
    isSubmitting = false;
    if (confirmSelectionButton) {
      confirmSelectionButton.disabled = false;
      confirmSelectionButton.textContent = 'Valider cette adresse';
    }
  }
}

checkButton.addEventListener('click', (event) => {
  event.preventDefault();
  handleDomainCheck();
});

form.addEventListener('submit', (event) => {
  event.preventDefault();
  submitSelection();
});

localInput.addEventListener('input', () => {
  validateLocalInput(true);
  updatePreview(true);
});

input.addEventListener('input', () => {
  resetSelectionState();
  updatePreview();
});

input.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') {
    event.preventDefault();
    handleDomainCheck();
  }
});

if (confirmSelectionButton) {
  confirmSelectionButton.addEventListener('click', () => {
    if (isSubmitting) return;
    if (!pendingDomain) {
      selectionError.textContent = 'Choisissez d’abord un domaine dans la liste.';
      return;
    }
    if (!validateLocalInput(true)) {
      selectionError.textContent = 'Corrigez le début de l’adresse avant de confirmer.';
      return;
    }
    confirmedDomain = pendingDomain;
    chosenDomainInput.value = confirmedDomain;
    selectionError.textContent = '';
    updateSelectionPreviewText();
    setStatus(`Adresse email confirmée : ${localInput.value}@${confirmedDomain}`, 'success');
    submitSelection();
  });
}

updatePreview(false);
if (sessionInput && sessionIdParam) {
  sessionInput.value = sessionIdParam;
}

if (existingDomainRadios.length && existingDomainInfo) {
  existingDomainRadios.forEach((r) => {
    r.addEventListener('change', () => {
      if (r.value === 'yes') {
        existingDomainInfo.style.display = 'block';
      } else {
        existingDomainInfo.style.display = 'none';
      }
    });
  });
  const initial = Array.from(existingDomainRadios).find((r) => r.checked);
  if (initial?.value === 'yes') {
    existingDomainInfo.style.display = 'block';
  }
}

async function guardCompletedState() {
  if (disableCompletionGuard || !hasAccessContext) return;
  try {
    const params = new URLSearchParams();
    if (sessionIdParam) params.set('session_id', sessionIdParam);
    if (emailParam) params.set('email', emailParam);
    const qs = params.toString();
    if (!qs) return;
    const response = await fetch(`${apiBase}/api/completion?${qs}`);
    const payload = await response.json();
    if (payload?.completed) {
      window.location.href = '/deja-complete';
    }
  } catch {
    // ignore check failures
  }
}

guardCompletedState();

const requiredFields = [
  {
    input: document.getElementById('fullName'),
    error: document.getElementById('fullName-error'),
    message: 'Indiquez votre prénom et nom.',
    hadValue: false,
  },
  {
    input: document.getElementById('company'),
    error: document.getElementById('company-error'),
    message: 'Indiquez le nom de votre entreprise.',
    hadValue: false,
  },
  {
    input: document.getElementById('currentEmail'),
    error: document.getElementById('currentEmail-error'),
    message: 'Indiquez votre adresse email actuelle.',
    hadValue: false,
  },
  {
    input: document.getElementById('displayName'),
    error: document.getElementById('displayName-error'),
    message: "Indiquez le nom d’expéditeur à afficher.",
    hadValue: false,
  },
];

function handleRequiredField(field) {
  const value = field.input?.value?.trim() || '';
  if (!field.error) return;
  if (value) {
    field.hadValue = true;
    field.error.textContent = '';
    return;
  }
  if (field.hadValue && !value) {
    field.error.textContent = field.message;
  } else {
    field.error.textContent = '';
  }
}

requiredFields.forEach((field) => {
  if (!field.input || !field.error) return;
  field.input.addEventListener('input', () => {
    handleRequiredField(field);
  });
  field.input.addEventListener('blur', () => {
    handleRequiredField(field);
  });
});
