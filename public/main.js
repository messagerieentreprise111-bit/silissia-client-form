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
const currentEmailInput = document.getElementById('currentEmail');
const currentEmailError = document.getElementById('currentEmail-error');
const currentEmailConfirmInput = document.getElementById('currentEmailConfirm');
const currentEmailConfirmError = document.getElementById('currentEmailConfirm-error');
const emailRegex =
  /^[\w.!#$%&'*+/=?^`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;

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
const sessionStorageKey = 'stripe_session_id';
let sessionIdParam = urlParams.get('session_id') || '';
let sessionSource = sessionIdParam ? 'url' : 'unknown';
if (sessionIdParam) {
  try {
    window.sessionStorage.setItem(sessionStorageKey, sessionIdParam);
  } catch {
    // ignore storage failures
  }
} else {
  try {
    const stored = window.sessionStorage.getItem(sessionStorageKey);
    if (stored) {
      sessionIdParam = stored;
      sessionSource = 'sessionStorage';
    }
  } catch {
    // ignore storage failures
  }
}
const appConfig = window.APP_CONFIG || {};
const disableCompletionGuard = Boolean(appConfig.disableCompletionGuard);
const completionRetryMaxMs = 60000;
const completionRetryDelayMs = 2000;

if (!disableCompletionGuard && !sessionIdParam) {
  window.location.href = '/acces-non-valide';
}

function clearSessionIdFromUrl() {
  if (!window.history?.replaceState) return;
  const url = new URL(window.location.href);
  if (!url.searchParams.has('session_id')) return;
  url.searchParams.delete('session_id');
  const clean = `${url.pathname}${url.searchParams.toString() ? `?${url.searchParams.toString()}` : ''}${url.hash}`;
  window.history.replaceState({}, '', clean);
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

function setInputError(inputEl, hasError) {
  if (!inputEl) return;
  inputEl.classList.toggle('input-error', Boolean(hasError));
}

let currentEmailTouched = false;
let currentEmailConfirmTouched = false;
function validateCurrentEmail(showMessage = false) {
  if (!currentEmailInput || !currentEmailError) return true;
  const value = (currentEmailInput.value || '').trim();
  const isValid = emailRegex.test(value);
  const shouldShow = showMessage || currentEmailTouched;

  if (!value) {
    const msg = shouldShow ? 'Indiquez votre adresse email actuelle.' : '';
    currentEmailError.textContent = msg;
    setInputError(currentEmailInput, shouldShow);
    currentEmailInput.setCustomValidity(msg);
    return false;
  }
  if (!isValid) {
    const msg = shouldShow ? 'Indiquez une adresse email valide (ex : prenom@domaine.fr).' : '';
    currentEmailError.textContent = msg;
    setInputError(currentEmailInput, shouldShow);
    currentEmailInput.setCustomValidity(msg);
    return false;
  }

  currentEmailError.textContent = '';
  setInputError(currentEmailInput, false);
  currentEmailInput.setCustomValidity('');
  return true;
}

function validateConfirmEmail(showMessage = false) {
  if (!currentEmailConfirmInput || !currentEmailConfirmError) return true;
  const value = (currentEmailConfirmInput.value || '').trim();
  const primary = (currentEmailInput?.value || '').trim();
  const isValid = emailRegex.test(value);
  const matches = isValid && emailRegex.test(primary) && value === primary;
  const shouldShow = showMessage || currentEmailConfirmTouched;

  if (!value) {
    const msg = shouldShow ? 'Confirmez votre adresse email.' : '';
    currentEmailConfirmError.textContent = msg;
    setInputError(currentEmailConfirmInput, shouldShow);
    currentEmailConfirmInput.setCustomValidity(msg);
    return false;
  }
  if (!isValid) {
    const msg = shouldShow ? 'Indiquez une adresse email valide (ex : prenom@domaine.fr).' : '';
    currentEmailConfirmError.textContent = msg;
    setInputError(currentEmailConfirmInput, shouldShow);
    currentEmailConfirmInput.setCustomValidity(msg);
    return false;
  }
  if (!matches) {
    const msg = shouldShow ? 'Les deux adresses ne correspondent pas.' : '';
    currentEmailConfirmError.textContent = msg;
    setInputError(currentEmailConfirmInput, shouldShow);
    currentEmailConfirmInput.setCustomValidity(msg);
    return false;
  }

  currentEmailConfirmError.textContent = '';
  setInputError(currentEmailConfirmInput, false);
  currentEmailConfirmInput.setCustomValidity('');
  return true;
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

function ensureFormComplete() {
  let ok = true;
  let firstInvalid = null;
  requiredFields.forEach((field) => {
    if (!field.input) return;
    field.hadValue = true;
    handleRequiredField(field);
    if (!field.input.value.trim()) {
      ok = false;
      if (!firstInvalid) firstInvalid = field.input;
    }
  });

  if (!validateCurrentEmail(true)) {
    ok = false;
    if (!firstInvalid && currentEmailInput) firstInvalid = currentEmailInput;
  }
  if (!validateConfirmEmail(true)) {
    ok = false;
    if (!firstInvalid && currentEmailConfirmInput) firstInvalid = currentEmailConfirmInput;
  }
  if (!validateLocalInput(true)) {
    ok = false;
    if (!firstInvalid && localInput) firstInvalid = localInput;
  }

  if (!Array.from(existingDomainRadios || []).some((r) => r.checked)) {
    ok = false;
    if (!firstInvalid && existingDomainInfo) {
      firstInvalid = existingDomainInfo.closest('fieldset') || existingDomainInfo;
    }
  }

  if (!ok) {
    setStatus('Merci de remplir tous les champs obligatoires avant de valider.', 'error');
    if (firstInvalid?.scrollIntoView) {
      firstInvalid.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    if (firstInvalid?.focus) {
      firstInvalid.focus({ preventScroll: true });
    }
  }
  return ok;
}

async function handleDomainCheck() {
  const domain = input.value.trim();
  const hpValue = honeypot.value.trim();
  if (isSubmitting) return;
  if (!validateCurrentEmail(true)) {
    setStatus('Indiquez une adresse email valide (ex : prenom@domaine.fr).', 'error');
    return;
  }
  if (!validateConfirmEmail(true)) {
    setStatus('Les deux adresses email doivent etre identiques et valides.', 'error');
    return;
  }
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
  if (!disableCompletionGuard && !sessionIdParam && !(sessionInput?.value || '').trim()) {
    setStatus('Effectuez le paiement avant de remplir le formulaire.', 'error');
    return;
  }
  if (!ensureFormComplete()) {
    return;
  }
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
  if (disableCompletionGuard || !sessionIdParam) return;
  const startedAt = Date.now();
  let currentDelayMs = completionRetryDelayMs;
  const attempt = async () => {
    try {
      const params = new URLSearchParams();
      if (sessionIdParam) params.set('session_id', sessionIdParam);
      if (sessionSource && sessionSource !== 'unknown') params.set('source', sessionSource);
      const qs = params.toString();
      if (!qs) return;
      const response = await fetch(`${apiBase}/api/completion?${qs}`);
      if (response.status === 429) {
        const elapsed = Date.now() - startedAt;
        if (elapsed < completionRetryMaxMs) {
          const retryAfter = Number(response.headers.get('Retry-After'));
          const nextDelay = Number.isFinite(retryAfter)
            ? Math.max(1000, retryAfter * 1000)
            : Math.min(currentDelayMs * 2, 10000);
          currentDelayMs = nextDelay;
          setStatus('Validation du paiement en cours. Merci de patienter...', 'notice');
          window.setTimeout(attempt, nextDelay);
          return;
        }
        window.location.href = '/acces-non-valide';
        return;
      }
      if (!response.ok) {
        window.location.href = '/acces-non-valide';
        return;
      }
      const payload = await response.json();
      if (payload?.state === 'retry') {
        const elapsed = Date.now() - startedAt;
        if (elapsed < completionRetryMaxMs) {
          setStatus('Validation du paiement en cours. Merci de patienter...', 'notice');
          const delay = Math.max(
            1000,
            Math.min(Number(payload.retryAfterMs) || completionRetryDelayMs, 8000)
          );
          currentDelayMs = delay;
          window.setTimeout(attempt, delay);
          return;
        }
        window.location.href = '/acces-non-valide';
        return;
      }
      if (!payload?.paid) {
        window.location.href = '/acces-non-valide';
        return;
      }
      clearSessionIdFromUrl();
      if (payload?.completed) {
        window.location.href = '/deja-complete';
      }
    } catch {
      // ignore check failures
    }
  };
  attempt();
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

if (currentEmailInput) {
  currentEmailInput.addEventListener('input', () => {
    validateCurrentEmail(false);
    if (currentEmailConfirmInput) {
      validateConfirmEmail(false);
    }
  });
  currentEmailInput.addEventListener('blur', () => {
    currentEmailTouched = true;
    validateCurrentEmail(true);
    if (currentEmailConfirmInput) {
      validateConfirmEmail(true);
    }
  });
}

if (currentEmailConfirmInput) {
  currentEmailConfirmInput.addEventListener('input', () => {
    validateConfirmEmail(false);
  });
  currentEmailConfirmInput.addEventListener('blur', () => {
    currentEmailConfirmTouched = true;
    validateConfirmEmail(true);
  });
}
