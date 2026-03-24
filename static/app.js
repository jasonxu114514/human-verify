const panelStage = document.getElementById("panelStage");
const panelCanvas = document.getElementById("panelCanvas");
const pieceCanvas = document.getElementById("pieceCanvas");
const sliderTrack = document.getElementById("sliderTrack");
const sliderFill = document.getElementById("sliderFill");
const sliderThumb = document.getElementById("sliderThumb");
const statusLine = document.getElementById("statusLine");
const refreshButton = document.getElementById("refreshButton");

const state = {
  challenge: null,
  panelImage: null,
  pieceImage: null,
  currentX: 0,
  dragging: false,
  dragStartX: 0,
  dragStartY: 0,
  dragStartHandle: 0,
  dragStartTime: 0,
  trace: [],
  busy: false,
  solved: false,
  proofSalt: "",
};

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

function round(value) {
  return Math.round(value * 100) / 100;
}

function setStatus(text, tone = "neutral") {
  statusLine.textContent = text;
  statusLine.dataset.tone = tone;
}

function getCookie(name) {
  const prefix = `${name}=`;
  const segments = document.cookie ? document.cookie.split("; ") : [];
  for (const segment of segments) {
    if (segment.startsWith(prefix)) {
      return decodeURIComponent(segment.slice(prefix.length));
    }
  }
  return "";
}

function randomHex(byteLength) {
  const bytes = new Uint8Array(byteLength);
  window.crypto.getRandomValues(bytes);
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  const digest = await window.crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest), (value) => value.toString(16).padStart(2, "0")).join("");
}

function formatProofNumber(value) {
  return Number(round(value).toFixed(2)).toFixed(2);
}

function collectClientSignals() {
  return {
    webDriver: Boolean(navigator.webdriver),
    userAgent: navigator.userAgent || "",
    language: navigator.language || "",
    platform: navigator.platform || "",
    timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone || "",
    hardwareConcurrency: navigator.hardwareConcurrency || 0,
    deviceMemory: navigator.deviceMemory ? Math.round(navigator.deviceMemory) : 0,
    screenWidth: window.screen.width || 0,
    screenHeight: window.screen.height || 0,
    colorDepth: window.screen.colorDepth || 0,
    cookieEnabled: navigator.cookieEnabled !== false,
  };
}

async function createJsProof(durationMs) {
  const attemptMarker = getCookie("hv_attempt");
  if (!attemptMarker) {
    throw new Error("attempt cookie missing");
  }
  if (!window.crypto?.subtle) {
    throw new Error("web crypto unavailable");
  }

  const clientSignals = collectClientSignals();
  const tracePayload = state.trace
    .map((point) => `${formatProofNumber(point.x)},${formatProofNumber(point.y)},${point.t}`)
    .join(";");
  const traceDigest = await sha256Hex(tracePayload);
  const proofSalt = state.proofSalt || randomHex(16);
  const powBundle = await solvePow(attemptMarker, proofSalt, state.challenge.powDifficulty);
  const proofInput = [
    state.challenge.token,
    state.challenge.proofNonce,
    attemptMarker,
    proofSalt,
    String(powBundle.powCounter),
    powBundle.powDigest,
    formatProofNumber(state.currentX),
    String(durationMs),
    traceDigest,
    clientSignals.userAgent,
    clientSignals.language,
    clientSignals.platform,
    clientSignals.timeZone,
    String(clientSignals.hardwareConcurrency),
    String(clientSignals.deviceMemory),
    String(clientSignals.screenWidth),
    String(clientSignals.screenHeight),
    String(clientSignals.colorDepth),
    String(clientSignals.cookieEnabled),
  ].join("|");

  return {
    powCounter: powBundle.powCounter,
    powDigest: powBundle.powDigest,
    proof: await sha256Hex(proofInput),
    proofSalt,
    clientSignals,
  };
}

async function solvePow(attemptMarker, proofSalt, difficulty) {
  const zeroPrefix = "0".repeat(Math.max(0, difficulty || 0));
  const maxIterations = 200000;

  for (let counter = 0; counter < maxIterations; counter += 1) {
    const payload = [
      state.challenge.token,
      state.challenge.proofNonce,
      attemptMarker,
      proofSalt,
      String(counter),
    ].join("|");
    const digest = await sha256Hex(payload);
    if (!zeroPrefix || digest.startsWith(zeroPrefix)) {
      return {
        powCounter: counter,
        powDigest: digest,
      };
    }
    if (counter > 0 && counter % 512 === 0) {
      await new Promise((resolve) => window.setTimeout(resolve, 0));
    }
  }

  throw new Error("pow solve failed");
}

function loadImage(url) {
  return new Promise((resolve, reject) => {
    const image = new Image();
    image.onload = () => resolve(image);
    image.onerror = () => reject(new Error(`image loading failed: ${url}`));
    image.src = url;
  });
}

function sliderTravel() {
  return Math.max(sliderTrack.clientWidth - sliderThumb.offsetWidth - 6, 1);
}

function handleLeftFromX(value) {
  if (!state.challenge) {
    return 0;
  }
  return (value / state.challenge.sliderMax) * sliderTravel();
}

function xFromHandleLeft(left) {
  if (!state.challenge) {
    return 0;
  }
  return (left / sliderTravel()) * state.challenge.sliderMax;
}

function panelScale() {
  if (!state.challenge) {
    return 1;
  }
  return panelStage.clientWidth / state.challenge.width;
}

function pieceDisplaySize() {
  if (!state.challenge) {
    return 0;
  }
  return state.challenge.pieceSize * panelScale();
}

function getCanvasContext(canvas, width, height) {
  const dpr = window.devicePixelRatio || 1;
  canvas.width = Math.max(1, Math.round(width * dpr));
  canvas.height = Math.max(1, Math.round(height * dpr));
  const context = canvas.getContext("2d");
  context.setTransform(dpr, 0, 0, dpr, 0, 0);
  context.clearRect(0, 0, width, height);
  return context;
}

function positionPiece() {
  if (!state.challenge) {
    return;
  }

  const handleLeft = handleLeftFromX(state.currentX);
  const thumbWidth = sliderThumb.offsetWidth;
  const size = pieceDisplaySize();

  sliderThumb.style.transform = `translate3d(${handleLeft}px, 0, 0)`;
  sliderFill.style.width = `${handleLeft + thumbWidth * 0.5}px`;
  pieceCanvas.style.width = `${size}px`;
  pieceCanvas.style.height = `${size}px`;
  pieceCanvas.style.top = `${state.challenge.pieceY * panelScale()}px`;
  pieceCanvas.style.transform = `translate3d(${state.currentX * panelScale()}px, 0, 0)`;
}

function renderPanel() {
  if (!state.challenge || !state.panelImage) {
    return;
  }

  const width = panelStage.clientWidth;
  const height = panelStage.clientHeight;
  const context = getCanvasContext(panelCanvas, width, height);
  context.drawImage(state.panelImage, 0, 0, width, height);
}

function renderPiece() {
  if (!state.challenge || !state.pieceImage) {
    return;
  }

  const size = pieceDisplaySize();
  const context = getCanvasContext(pieceCanvas, size, size);
  context.drawImage(state.pieceImage, 0, 0, size, size);
}

function renderCanvases() {
  renderPanel();
  renderPiece();
  positionPiece();
}

function resetSlider() {
  state.currentX = 0;
  state.trace = [];
  state.proofSalt = "";
  sliderThumb.classList.remove("is-dragging");
  positionPiece();
}

function pushTraceSample(pointerEvent) {
  const elapsed = Math.round(performance.now() - state.dragStartTime);
  const sample = {
    x: round(state.currentX),
    y: round(pointerEvent.clientY - state.dragStartY),
    t: elapsed,
  };
  const last = state.trace[state.trace.length - 1];
  if (
    last &&
    Math.abs(last.x - sample.x) < 0.75 &&
    Math.abs(last.y - sample.y) < 0.75 &&
    sample.t - last.t < 14
  ) {
    return;
  }
  state.trace.push(sample);
  if (state.trace.length > 180) {
    state.trace.splice(1, 1);
  }
}

async function loadCaptcha() {
  if (state.busy) {
    return;
  }

  state.busy = true;
  state.solved = false;
  refreshButton.disabled = true;
  sliderThumb.disabled = true;
  setStatus("Preparing a new scenic puzzle...", "neutral");

  try {
    const response = await fetch("/api/captcha/new", { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`request failed: ${response.status}`);
    }

    state.challenge = await response.json();
    const panelURL = `${state.challenge.panelUrl}?t=${encodeURIComponent(state.challenge.token)}`;
    const pieceURL = `${state.challenge.pieceUrl}?t=${encodeURIComponent(state.challenge.token)}`;
    const [panelImage, pieceImage] = await Promise.all([
      loadImage(panelURL),
      loadImage(pieceURL),
    ]);
    state.panelImage = panelImage;
    state.pieceImage = pieceImage;
    resetSlider();
    renderCanvases();
    sliderThumb.disabled = false;
    setStatus("Drag the slider and align the piece with the slot.", "neutral");
  } catch (error) {
    console.error(error);
    setStatus("Captcha loading failed. Try again later.", "error");
  } finally {
    refreshButton.disabled = false;
    state.busy = false;
  }
}

async function verifyCaptcha() {
  if (!state.challenge || state.busy) {
    return;
  }

  state.busy = true;
  sliderThumb.disabled = true;
  refreshButton.disabled = true;
  setStatus("Analyzing drag trace and alignment...", "neutral");

  const durationMs = state.trace.length ? state.trace[state.trace.length - 1].t : 0;

  try {
    const proofBundle = await createJsProof(durationMs);
    const response = await fetch("/api/captcha/verify", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        token: state.challenge.token,
        sliderX: round(state.currentX),
        durationMs,
        trace: state.trace,
        powCounter: proofBundle.powCounter,
        powDigest: proofBundle.powDigest,
        proof: proofBundle.proof,
        proofSalt: proofBundle.proofSalt,
        clientSignals: proofBundle.clientSignals,
      }),
    });

    const payload = await response.json();
    if (payload.success) {
      state.solved = true;
      setStatus("Verification passed. You can now wire this flow into your form.", "success");
      return;
    }

    setStatus("Verification failed. A new puzzle is being prepared.", "error");
    window.setTimeout(() => {
      loadCaptcha();
    }, 850);
  } catch (error) {
    console.error(error);
    setStatus("Verification request failed. Reloading a new puzzle.", "error");
    window.setTimeout(() => {
      loadCaptcha();
    }, 850);
  } finally {
    state.busy = false;
    refreshButton.disabled = false;
    if (!state.solved) {
      sliderThumb.disabled = false;
    }
  }
}

function onPointerDown(event) {
  if (!state.challenge || state.busy || state.solved) {
    return;
  }

  state.dragging = true;
  state.dragStartX = event.clientX;
  state.dragStartY = event.clientY;
  state.dragStartHandle = handleLeftFromX(state.currentX);
  state.dragStartTime = performance.now();
  state.proofSalt = randomHex(16);
  state.trace = [{ x: round(state.currentX), y: 0, t: 0 }];

  sliderThumb.classList.add("is-dragging");
  sliderThumb.setPointerCapture(event.pointerId);
  setStatus("Keep dragging until the piece locks into the slot.", "neutral");
}

function onPointerMove(event) {
  if (!state.dragging || !state.challenge || state.busy) {
    return;
  }

  const delta = event.clientX - state.dragStartX;
  const nextLeft = clamp(state.dragStartHandle + delta, 0, sliderTravel());
  state.currentX = xFromHandleLeft(nextLeft);
  positionPiece();
  pushTraceSample(event);
}

function onPointerUp(event) {
  if (!state.dragging) {
    return;
  }

  state.dragging = false;
  sliderThumb.classList.remove("is-dragging");
  try {
    sliderThumb.releasePointerCapture(event.pointerId);
  } catch (error) {
    console.debug(error);
  }

  pushTraceSample(event);
  if (state.currentX < 12) {
    resetSlider();
    setStatus("The slider did not move far enough. Drag it again.", "neutral");
    return;
  }

  verifyCaptcha();
}

sliderThumb.addEventListener("pointerdown", onPointerDown);
sliderThumb.addEventListener("pointermove", onPointerMove);
sliderThumb.addEventListener("pointerup", onPointerUp);
sliderThumb.addEventListener("pointercancel", onPointerUp);
refreshButton.addEventListener("click", loadCaptcha);
window.addEventListener("resize", renderCanvases);

if ("ResizeObserver" in window) {
  const observer = new ResizeObserver(() => renderCanvases());
  observer.observe(panelStage);
  observer.observe(sliderTrack);
}

loadCaptcha();
