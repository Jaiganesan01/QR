/**
 * QShield Interactive Scanner Client Script
 * Complete QR Security Report UI, live OpenCV decoding, static URL heuristic analysis,
 * copy-to-clipboard, non-URL payload guidance, and accessible indicator details.
 */

document.addEventListener('DOMContentLoaded', () => {
  // Elements: Navigation / Tab Switching
  const tabCamera = document.getElementById('tabCamera');
  const tabUpload = document.getElementById('tabUpload');
  const tabManual = document.getElementById('tabManual');
  const panelCamera = document.getElementById('panelCamera');
  const panelUpload = document.getElementById('panelUpload');
  const panelManual = document.getElementById('panelManual');

  function activateTab(activeTab, activePanel) {
    [
      { tab: tabCamera, panel: panelCamera },
      { tab: tabUpload, panel: panelUpload },
      { tab: tabManual, panel: panelManual }
    ].forEach(({ tab, panel }) => {
      if (!tab || !panel) return;
      if (tab === activeTab) {
        tab.classList.add('active');
        tab.setAttribute('aria-selected', 'true');
        panel.style.display = 'block';
      } else {
        tab.classList.remove('active');
        tab.setAttribute('aria-selected', 'false');
        panel.style.display = 'none';
      }
    });

    // If leaving camera tab, safely stop hardware camera stream
    if (activeTab !== tabCamera && typeof stopCamera === 'function') {
      stopCamera();
    }
  }

  if (tabCamera) {
    tabCamera.addEventListener('click', () => activateTab(tabCamera, panelCamera));
  }
  if (tabUpload) {
    tabUpload.addEventListener('click', () => activateTab(tabUpload, panelUpload));
  }
  if (tabManual) {
    tabManual.addEventListener('click', () => activateTab(tabManual, panelManual));
  }

  // Elements: QR Payload Inspector (Prompt 11)
  const payloadInspectorCard = document.getElementById('payloadInspectorCard');
  const inspectorCategoryBadge = document.getElementById('inspectorCategoryBadge');
  const inspectorConfidenceBadge = document.getElementById('inspectorConfidenceBadge');
  const inspectorSummaryText = document.getElementById('inspectorSummaryText');
  const inspectorFieldsList = document.getElementById('inspectorFieldsList');
  const inspectorWarningsBox = document.getElementById('inspectorWarningsBox');
  const inspectorWarningsList = document.getElementById('inspectorWarningsList');
  const inspectorLimitationsText = document.getElementById('inspectorLimitationsText');

  function renderPayloadInspection(classification) {
    if (!payloadInspectorCard || !classification) return;

    const displayName = classification.display_name || 'Generic Payload';
    const confidence = classification.classification_confidence || 'medium';
    const summary = classification.summary || '';
    const fields = classification.fields || {};
    const warnings = classification.warnings || [];
    const limitations = classification.limitations || '';

    if (inspectorCategoryBadge) {
      inspectorCategoryBadge.textContent = displayName;
    }
    if (inspectorConfidenceBadge) {
      inspectorConfidenceBadge.textContent = `Confidence: ${confidence.toUpperCase()}`;
    }
    if (inspectorSummaryText) {
      inspectorSummaryText.textContent = summary;
    }

    // Render Fields Grid
    if (inspectorFieldsList) {
      inspectorFieldsList.innerHTML = '';
      const fieldKeys = Object.keys(fields);
      if (fieldKeys.length === 0) {
        const noFields = document.createElement('div');
        noFields.style.color = 'var(--color-text-secondary)';
        noFields.style.fontSize = '0.825rem';
        noFields.textContent = 'No structured subfields extracted.';
        inspectorFieldsList.appendChild(noFields);
      } else {
        fieldKeys.forEach(key => {
          const val = fields[key];
          if (val === null || val === undefined) return;

          const itemBox = document.createElement('div');
          itemBox.className = 'card';
          itemBox.style.padding = 'var(--space-sm)';
          itemBox.style.backgroundColor = 'var(--color-surface-muted)';

          const keyLabel = document.createElement('div');
          keyLabel.style.fontSize = '0.75rem';
          keyLabel.style.fontWeight = '700';
          keyLabel.style.textTransform = 'uppercase';
          keyLabel.style.color = 'var(--color-text-secondary)';
          keyLabel.textContent = key.replace(/_/g, ' ');

          const valText = document.createElement('div');
          valText.style.fontSize = '0.875rem';
          valText.style.fontWeight = '600';
          valText.style.wordBreak = 'break-word';
          valText.style.color = 'var(--color-text-primary)';
          valText.textContent = typeof val === 'boolean' ? (val ? 'Yes' : 'No') : String(val);

          itemBox.appendChild(keyLabel);
          itemBox.appendChild(valText);
          inspectorFieldsList.appendChild(itemBox);
        });
      }
    }

    // Render Warnings
    if (inspectorWarningsBox && inspectorWarningsList) {
      inspectorWarningsList.innerHTML = '';
      if (warnings.length > 0) {
        warnings.forEach(w => {
          const li = document.createElement('li');
          li.textContent = w;
          inspectorWarningsList.appendChild(li);
        });
        inspectorWarningsBox.style.display = 'block';
      } else {
        inspectorWarningsBox.style.display = 'none';
      }
    }

    if (inspectorLimitationsText) {
      inspectorLimitationsText.textContent = `Parser Scope: ${limitations}`;
    }

    payloadInspectorCard.style.display = 'block';
  }

  // Elements: File Upload Elements
  const dropzone = document.getElementById('qrDropzone');
  const fileInput = document.getElementById('qrFileInput');
  const browseFileBtn = document.getElementById('browseFileBtn');
  const previewBox = document.getElementById('previewBox');
  const previewThumb = document.getElementById('previewThumb');
  const previewName = document.getElementById('previewName');
  const previewSize = document.getElementById('previewSize');
  const removeFileBtn = document.getElementById('removeFileBtn');
  const uploadFeedback = document.getElementById('uploadFeedback');
  const btnScanFile = document.getElementById('btnScanFile');
  const btnScanText = document.getElementById('btnScanText');
  const qrUploadForm = document.getElementById('qrUploadForm');

  // Camera Placeholder Elements
  const btnUseCamera = document.getElementById('btnUseCamera');
  const cameraNotice = document.getElementById('cameraNotice');

  // Manual URL Elements
  const manualUrlInput = document.getElementById('manualUrlInput');
  const urlFeedback = document.getElementById('urlFeedback');
  const btnScanUrl = document.getElementById('btnScanUrl');
  const manualUrlForm = document.getElementById('manualUrlForm');

  // Staging / Results Elements
  const resultsStagingArea = document.getElementById('resultsStagingArea');
  const stagedPayloadContent = document.getElementById('stagedPayloadContent');
  const stagedPayloadType = document.getElementById('stagedPayloadType');
  const truncationNotice = document.getElementById('truncationNotice');
  const payloadContextNotice = document.getElementById('payloadContextNotice');
  const payloadContextText = document.getElementById('payloadContextText');
  const reportStatusSummary = document.getElementById('reportStatusSummary');
  const reportTimestamp = document.getElementById('reportTimestamp');

  // Copy Payload Elements
  const btnCopyPayload = document.getElementById('btnCopyPayload');
  const copyBtnText = document.getElementById('copyBtnText');
  const copyAlertNotice = document.getElementById('copyAlertNotice');

  // URL Analysis Elements
  const analyzeUrlActionBox = document.getElementById('analyzeUrlActionBox');
  const btnAnalyzeDecodedUrl = document.getElementById('btnAnalyzeDecodedUrl');
  const btnAnalyzeText = document.getElementById('btnAnalyzeText');
  const urlAnalysisResultsPanel = document.getElementById('urlAnalysisResultsPanel');
  const indicatorsCountBadge = document.getElementById('indicatorsCountBadge');
  const indicatorsList = document.getElementById('indicatorsList');
  const btnScanAnotherTop = document.getElementById('btnScanAnotherTop');
  const btnScanAnotherBottom = document.getElementById('btnScanAnotherBottom');
  const btnPdfPlaceholder = document.getElementById('btnPdfPlaceholder');

  // Supported Extensions & 5MB Limit
  const ALLOWED_MIME_TYPES = ['image/png', 'image/jpeg', 'image/jpg', 'image/webp'];
  const ALLOWED_EXTENSIONS = ['.png', '.jpg', '.jpeg', '.webp'];
  const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB in bytes

  let currentObjectURL = null;
  let activeDecodedPayload = null;
  let activePayloadType = null;
  let activeScanResult = null;

  function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  function showError(element, msg) {
    if (!element) return;
    element.textContent = msg;
    element.classList.add('error');
    element.style.display = 'block';
  }

  function clearError(element) {
    if (!element) return;
    element.textContent = '';
    element.classList.remove('error');
    element.style.display = 'none';
  }

  function revokeCurrentObjectURL() {
    if (currentObjectURL) {
      URL.revokeObjectURL(currentObjectURL);
      currentObjectURL = null;
    }
  }

  function resetScanner() {
    revokeCurrentObjectURL();
    activeDecodedPayload = null;
    activePayloadType = null;
    if (fileInput) fileInput.value = '';
    if (previewBox) previewBox.classList.remove('active');
    if (dropzone) dropzone.style.display = 'block';
    if (previewThumb) previewThumb.src = '';
    if (btnScanFile) {
      btnScanFile.setAttribute('disabled', 'true');
      if (btnScanText) btnScanText.textContent = 'Decode QR Code';
    }
    if (resultsStagingArea) resultsStagingArea.style.display = 'none';
    if (truncationNotice) truncationNotice.style.display = 'none';
    if (urlAnalysisResultsPanel) urlAnalysisResultsPanel.style.display = 'none';
    if (analyzeUrlActionBox) analyzeUrlActionBox.style.display = 'none';
    if (payloadContextNotice) payloadContextNotice.style.display = 'none';
    if (copyAlertNotice) copyAlertNotice.style.display = 'none';

    // Camera view reset
    if (typeof cameraReticle !== 'undefined' && cameraReticle) {
      cameraReticle.classList.remove('detected');
    }
    if (typeof btnCameraScanAgain !== 'undefined' && btnCameraScanAgain) {
      btnCameraScanAgain.style.display = 'none';
    }
    if (typeof isCameraActive !== 'undefined' && isCameraActive) {
      isDetecting = true;
      if (typeof updateCameraStatus === 'function') updateCameraStatus('active', 'Scanning Live');
      if (typeof reticleInstruction !== 'undefined' && reticleInstruction) {
        reticleInstruction.textContent = 'Point camera at a QR code to decode';
      }
    }

    // Scroll back to scanner card
    const scannerInputCard = document.getElementById('scannerInputCard');
    if (scannerInputCard) {
      scannerInputCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  if (btnScanAnotherTop) btnScanAnotherTop.addEventListener('click', resetScanner);
  if (btnScanAnotherBottom) btnScanAnotherBottom.addEventListener('click', resetScanner);

  // Copy Decoded Content safely to clipboard
  if (btnCopyPayload) {
    btnCopyPayload.addEventListener('click', async () => {
      if (!activeDecodedPayload) return;
      try {
        await navigator.clipboard.writeText(activeDecodedPayload);
        if (copyBtnText) copyBtnText.textContent = 'Copied!';
        if (copyAlertNotice) {
          copyAlertNotice.style.display = 'block';
          setTimeout(() => {
            copyAlertNotice.style.display = 'none';
            if (copyBtnText) copyBtnText.textContent = 'Copy Content';
          }, 3000);
        }
      } catch (err) {
        // Fallback for older browsers
        const textarea = document.createElement('textarea');
        textarea.value = activeDecodedPayload;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        if (copyBtnText) copyBtnText.textContent = 'Copied!';
        setTimeout(() => {
          if (copyBtnText) copyBtnText.textContent = 'Copy Content';
        }, 3000);
      }
    });
  }

  // PDF Report Download click handler
  if (btnPdfPlaceholder) {
    btnPdfPlaceholder.addEventListener('click', async (e) => {
      e.preventDefault();
      
      const payloadToSend = activeScanResult || {
        scan_id: 'live',
        valid: true,
        target_domain: activeDecodedPayload ? activeDecodedPayload.substring(0, 100) : 'None',
        payload_type: activePayloadType || 'Unknown',
        risk_assessment: {
          score: null,
          risk_level: 'inconclusive',
          recommendations: { next_step: 'Independently verify destination authenticity.' }
        },
        indicators: []
      };

      try {
        btnPdfPlaceholder.setAttribute('disabled', 'true');
        const originalText = btnPdfPlaceholder.querySelector('span').textContent;
        btnPdfPlaceholder.querySelector('span').textContent = 'Generating PDF...';

        const res = await fetch('/api/scan-report/generate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payloadToSend)
        });

        if (res.ok) {
          const blob = await res.blob();
          const blobUrl = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = blobUrl;
          a.download = `QShield-Security-Report-${payloadToSend.scan_id || 'live'}.pdf`;
          document.body.appendChild(a);
          a.click();
          a.remove();
          window.URL.revokeObjectURL(blobUrl);
        } else {
          const errData = await res.json().catch(() => ({}));
          alert(errData.message || 'Failed to generate PDF report.');
        }
      } catch (err) {
        console.error('PDF generation error:', err);
        alert('An error occurred while generating the PDF report.');
      } finally {
        btnPdfPlaceholder.removeAttribute('disabled');
        btnPdfPlaceholder.querySelector('span').textContent = 'Download PDF Security Report';
      }
    });
  }

  function isAllowedFile(file) {
    if (!file) return false;
    const name = file.name.toLowerCase();
    const hasValidExt = ALLOWED_EXTENSIONS.some(ext => name.endsWith(ext));
    const hasValidMime = ALLOWED_MIME_TYPES.includes(file.type.toLowerCase()) || file.type === '';
    return hasValidExt && hasValidMime;
  }

  function handleFile(file) {
    clearError(uploadFeedback);
    if (cameraNotice) cameraNotice.style.display = 'none';

    if (!file) {
      showError(uploadFeedback, 'No file selected. Please select a QR image to inspect.');
      resetScanner();
      return;
    }

    if (!isAllowedFile(file)) {
      showError(uploadFeedback, 'Unsupported file format. Please select a valid PNG, JPG, JPEG, or WebP image.');
      resetScanner();
      return;
    }

    if (file.size > MAX_FILE_SIZE) {
      showError(uploadFeedback, `File exceeds the 5 MB maximum limit (${formatBytes(file.size)}). Please choose a smaller image.`);
      resetScanner();
      return;
    }

    if (file.size === 0) {
      showError(uploadFeedback, 'The selected file appears to be empty. Please choose a valid image.');
      resetScanner();
      return;
    }

    revokeCurrentObjectURL();

    try {
      currentObjectURL = URL.createObjectURL(file);
      previewThumb.src = currentObjectURL;
      previewName.textContent = file.name;
      previewSize.textContent = formatBytes(file.size);
      previewBox.classList.add('active');
      dropzone.style.display = 'none';
      btnScanFile.removeAttribute('disabled');
      clearError(uploadFeedback);
    } catch (e) {
      showError(uploadFeedback, 'Unable to create image preview. Please try another file.');
      resetScanner();
    }
  }

  // Dropzone drag-and-drop & file picker events
  if (dropzone && fileInput) {
    dropzone.addEventListener('click', (e) => {
      if (e.target !== browseFileBtn) {
        fileInput.click();
      }
    });

    dropzone.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        fileInput.click();
      }
    });

    if (browseFileBtn) {
      browseFileBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        fileInput.click();
      });
    }

    dropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.add('dragover');
    });

    dropzone.addEventListener('dragleave', () => {
      dropzone.classList.remove('dragover');
    });

    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.remove('dragover');
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        const file = e.dataTransfer.files[0];
        fileInput.files = e.dataTransfer.files;
        handleFile(file);
      }
    });

    fileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files.length > 0) {
        handleFile(e.target.files[0]);
      }
    });
  }

  if (removeFileBtn) {
    removeFileBtn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      resetScanner();
      clearError(uploadFeedback);
    });
  }

  let activeScanSource = 'upload';

  /**
   * Renders decoded QR results securely and triggers safe analysis pipeline.
   * STRICT SECURITY GUARANTEE: Never opens, executes, navigates to, or fetches the scanned payload.
   */
  function displayDecodedResult(data, scanSource = 'upload') {
    activeScanSource = scanSource;
    activeDecodedPayload = data.decoded_content || '';
    activePayloadType = data.payload_type || 'Payload';

    if (stagedPayloadContent) {
      stagedPayloadContent.textContent = activeDecodedPayload; // Safe textContent, no HTML injection
    }
    if (stagedPayloadType) {
      stagedPayloadType.textContent = activePayloadType;
    }
    if (truncationNotice) {
      truncationNotice.style.display = data.truncated ? 'block' : 'none';
    }
    if (reportTimestamp) {
      reportTimestamp.textContent = new Date().toLocaleTimeString();
    }

    // Structured QR Payload Inspector
    if (data.classification) {
      renderPayloadInspection(data.classification);
    } else if (payloadInspectorCard) {
      payloadInspectorCard.style.display = 'none';
    }

    // Determine if payload is an HTTP/HTTPS URL
    const trimmed = activeDecodedPayload.trim();
    const isUrl = (
      activePayloadType === 'URL' ||
      activePayloadType === 'URL (No Scheme)' ||
      /^https?:\/\//i.test(trimmed) ||
      /^(www\.|[a-zA-Z0-9-]+\.[a-zA-Z]{2,})([/?#]|$)/i.test(trimmed)
    );

    if (isUrl) {
      if (reportStatusSummary) reportStatusSummary.textContent = "Web Link Ready for Analysis";
      if (analyzeUrlActionBox) analyzeUrlActionBox.style.display = 'flex';
      if (payloadContextNotice) payloadContextNotice.style.display = 'none';
      // Automatically trigger safe in-memory heuristic analysis (NEVER navigates or fetches destination)
      performUrlAnalysis(activeDecodedPayload, scanSource);
    } else {
      // Non-URL payload: Plain text, Wi-Fi, vCard, Payment/UPI, etc.
      if (reportStatusSummary) reportStatusSummary.textContent = `Non-URL Payload: ${activePayloadType}`;
      if (analyzeUrlActionBox) analyzeUrlActionBox.style.display = 'none';
      if (urlAnalysisResultsPanel) urlAnalysisResultsPanel.style.display = 'none';

      if (payloadContextNotice && payloadContextText) {
        if (activePayloadType.includes('Wi-Fi')) {
          payloadContextText.innerHTML = "<strong>Wi-Fi Network Configuration:</strong> This QR code contains wireless network credentials. QShield has decoded the text safely; it will not automatically connect your device to this network.";
        } else if (activePayloadType.includes('Payment') || activePayloadType.includes('UPI')) {
          payloadContextText.innerHTML = "<strong>Payment Intent:</strong> This QR code initiates a financial payment intent. Verify the recipient account ID carefully before submitting any funds in your payment application.";
        } else if (activePayloadType.includes('Contact')) {
          payloadContextText.innerHTML = "<strong>Contact Information (vCard):</strong> This QR code encodes contact card details. It has been rendered safely as text without modifying your device address book.";
        } else {
          payloadContextText.innerHTML = "<strong>Plain Text Content:</strong> This QR code contains informational text rather than a web link. URL-specific security heuristics are not applicable.";
        }
        payloadContextNotice.style.display = 'block';
      }
    }

    if (resultsStagingArea) {
      resultsStagingArea.style.display = 'block';
      resultsStagingArea.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }

  // =========================================================================
  // Live Camera QR Scanner Controller (Prompt 20)
  // =========================================================================
  const cameraVideo = document.getElementById('cameraVideo');
  const cameraCanvas = document.getElementById('cameraCanvas');
  const cameraOverlay = document.getElementById('cameraOverlay');
  const cameraReticle = document.getElementById('cameraReticle');
  const cameraPlaceholder = document.getElementById('cameraPlaceholder');
  const cameraStatusBadge = document.getElementById('cameraStatusBadge');
  const cameraStatusText = document.getElementById('cameraStatusText');
  const cameraDeviceSelect = document.getElementById('cameraDeviceSelect');
  const btnSwitchCamera = document.getElementById('btnSwitchCamera');
  const btnStartCamera = document.getElementById('btnStartCamera');
  const btnStopCamera = document.getElementById('btnStopCamera');
  const btnCameraScanAgain = document.getElementById('btnCameraScanAgain');
  const cameraFeedback = document.getElementById('cameraFeedback');
  const reticleInstruction = document.getElementById('reticleInstruction');

  let mediaStream = null;
  let isCameraActive = false;
  let isDetecting = false;
  let detectionIntervalTimer = null;
  let isCanvasFallbackDecoding = false;
  let lastDecodedPayload = null;
  let lastDecodedTime = 0;
  const DUPLICATE_COOLDOWN_MS = 3000;
  let availableVideoDevices = [];
  let currentDeviceIndex = 0;

  // Initialize browser-native BarcodeDetector if available
  let barcodeDetector = null;
  let hasBarcodeDetector = false;
  if (typeof window !== 'undefined' && 'BarcodeDetector' in window) {
    try {
      barcodeDetector = new window.BarcodeDetector({ formats: ['qr_code'] });
      hasBarcodeDetector = true;
    } catch (e) {
      hasBarcodeDetector = false;
    }
  }

  function updateCameraStatus(state, label) {
    if (!cameraStatusBadge || !cameraStatusText) return;
    cameraStatusText.textContent = label;
    cameraStatusBadge.className = 'camera-status-badge';
    if (state === 'active') {
      cameraStatusBadge.classList.add('active');
    } else if (state === 'paused') {
      cameraStatusBadge.classList.add('paused');
    } else if (state === 'error' || state === 'denied') {
      cameraStatusBadge.classList.add('error');
    }
  }

  async function updateDeviceList() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) return;
    try {
      const devices = await navigator.mediaDevices.enumerateDevices();
      availableVideoDevices = devices.filter(d => d.kind === 'videoinput');
      if (cameraDeviceSelect && availableVideoDevices.length > 1) {
        cameraDeviceSelect.innerHTML = '';
        availableVideoDevices.forEach((dev, idx) => {
          const opt = document.createElement('option');
          opt.value = dev.deviceId;
          opt.textContent = dev.label || `Camera ${idx + 1}`;
          cameraDeviceSelect.appendChild(opt);
        });
        cameraDeviceSelect.style.display = 'inline-block';
        if (btnSwitchCamera) btnSwitchCamera.style.display = 'inline-flex';
      } else {
        if (cameraDeviceSelect) cameraDeviceSelect.style.display = 'none';
        if (btnSwitchCamera) btnSwitchCamera.style.display = 'none';
      }
    } catch (e) {
      // Ignore device enumeration errors in restricted sandboxes
    }
  }

  async function startCamera(preferredDeviceId = null) {
    clearError(cameraFeedback);

    // Security context requirement: HTTPS or localhost
    const isLocalhost = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
    if (!window.isSecureContext && !isLocalhost) {
      showError(cameraFeedback, 'Camera access requires a secure connection (HTTPS or localhost). Please upload a QR image or enter a URL manually.');
      updateCameraStatus('error', 'Insecure Context');
      return;
    }

    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      showError(cameraFeedback, 'Your browser does not support live camera capture. Please upload a QR image or analyze a URL manually.');
      updateCameraStatus('error', 'Unsupported');
      return;
    }

    stopCamera();

    updateCameraStatus('starting', 'Requesting Access...');
    if (btnStartCamera) btnStartCamera.setAttribute('disabled', 'true');

    const constraints = {
      audio: false,
      video: preferredDeviceId
        ? { deviceId: { exact: preferredDeviceId }, width: { ideal: 1280 }, height: { ideal: 720 } }
        : { facingMode: { ideal: 'environment' }, width: { ideal: 1280 }, height: { ideal: 720 } }
    };

    try {
      mediaStream = await navigator.mediaDevices.getUserMedia(constraints);
      if (cameraVideo) {
        cameraVideo.srcObject = mediaStream;
        await new Promise((resolve) => {
          cameraVideo.onloadedmetadata = () => {
            cameraVideo.play().then(resolve).catch(resolve);
          };
        });
      }

      isCameraActive = true;
      isDetecting = true;

      if (cameraPlaceholder) cameraPlaceholder.style.display = 'none';
      if (cameraOverlay) cameraOverlay.style.display = 'flex';
      if (btnStartCamera) {
        btnStartCamera.style.display = 'none';
        btnStartCamera.removeAttribute('disabled');
      }
      if (btnStopCamera) btnStopCamera.style.display = 'inline-flex';
      if (btnCameraScanAgain) btnCameraScanAgain.style.display = 'none';
      if (cameraReticle) cameraReticle.classList.remove('detected');
      if (reticleInstruction) reticleInstruction.textContent = 'Point camera at a QR code to decode';

      updateCameraStatus('active', 'Scanning Live');
      await updateDeviceList();
      startDetectionLoop();
    } catch (err) {
      console.warn('Camera access error:', err);
      if (btnStartCamera) {
        btnStartCamera.removeAttribute('disabled');
        btnStartCamera.style.display = 'inline-flex';
      }
      if (btnStopCamera) btnStopCamera.style.display = 'none';

      let msg = 'Unable to access camera.';
      if (err.name === 'NotAllowedError' || err.name === 'PermissionDeniedError') {
        msg = 'Camera permission was denied. Please allow camera permissions in your browser address bar settings to scan live, or upload a QR image below.';
        updateCameraStatus('denied', 'Permission Denied');
      } else if (err.name === 'NotFoundError' || err.name === 'DevicesNotFoundError') {
        msg = 'No camera device detected on this system. You can upload a QR image or enter a URL manually.';
        updateCameraStatus('error', 'No Camera');
      } else if (err.name === 'NotReadableError' || err.name === 'TrackStartError') {
        msg = 'Camera is currently in use by another application. Please close the other program and try again.';
        updateCameraStatus('error', 'Camera Busy');
      } else {
        msg = `Camera error (${err.name || 'Unknown'}). Please choose an image file instead.`;
        updateCameraStatus('error', 'Error');
      }
      showError(cameraFeedback, msg);
    }
  }

  function stopCamera() {
    stopDetectionLoop();
    if (mediaStream) {
      mediaStream.getTracks().forEach(track => {
        try { track.stop(); } catch (e) {}
      });
      mediaStream = null;
    }
    if (cameraVideo) {
      cameraVideo.srcObject = null;
    }
    isCameraActive = false;
    isDetecting = false;

    if (cameraPlaceholder) cameraPlaceholder.style.display = 'block';
    if (cameraOverlay) cameraOverlay.style.display = 'none';
    if (btnStartCamera) {
      btnStartCamera.style.display = 'inline-flex';
      btnStartCamera.removeAttribute('disabled');
    }
    if (btnStopCamera) btnStopCamera.style.display = 'none';
    if (btnCameraScanAgain) btnCameraScanAgain.style.display = 'none';
    if (cameraReticle) cameraReticle.classList.remove('detected');

    updateCameraStatus('idle', 'Camera Off');
  }

  function startDetectionLoop() {
    stopDetectionLoop();
    // 120ms interval for native client-side BarcodeDetector, 650ms for canvas backend fallback
    const intervalMs = hasBarcodeDetector ? 120 : 650;
    detectionIntervalTimer = setInterval(detectionTick, intervalMs);
  }

  function stopDetectionLoop() {
    if (detectionIntervalTimer) {
      clearInterval(detectionIntervalTimer);
      detectionIntervalTimer = null;
    }
  }

  async function detectionTick() {
    if (!isCameraActive || !isDetecting || !cameraVideo) return;
    if (cameraVideo.readyState < 2) return;

    if (hasBarcodeDetector && barcodeDetector) {
      try {
        const barcodes = await barcodeDetector.detect(cameraVideo);
        if (barcodes && barcodes.length > 0 && isDetecting) {
          const raw = barcodes[0].rawValue;
          if (raw) {
            handleCameraDetection(raw);
          }
        }
      } catch (err) {
        // Graceful fallback to backend canvas capture on unexpected failure
        captureAndDecodeFrameFallback();
      }
    } else {
      captureAndDecodeFrameFallback();
    }
  }

  async function captureAndDecodeFrameFallback() {
    if (!isCameraActive || !isDetecting || isCanvasFallbackDecoding || !cameraVideo || !cameraCanvas) return;
    if (cameraVideo.videoWidth === 0 || cameraVideo.videoHeight === 0) return;

    isCanvasFallbackDecoding = true;
    try {
      // Downscale frame to max 640px dimension for rapid transmission and OpenCV processing
      const maxDim = Math.max(cameraVideo.videoWidth, cameraVideo.videoHeight);
      const scale = maxDim > 640 ? 640 / maxDim : 1;
      cameraCanvas.width = Math.round(cameraVideo.videoWidth * scale);
      cameraCanvas.height = Math.round(cameraVideo.videoHeight * scale);

      const ctx = cameraCanvas.getContext('2d');
      ctx.drawImage(cameraVideo, 0, 0, cameraCanvas.width, cameraCanvas.height);
      const frameBase64 = cameraCanvas.toDataURL('image/jpeg', 0.65);

      const response = await fetch('/api/decode-qr', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ frame: frameBase64, scan_type: 'camera' })
      });

      if (response.ok) {
        const data = await response.json();
        if (data.success && data.decoded_content && isDetecting) {
          handleCameraDetection(data.decoded_content, data.payload_type, data.classification);
        }
      }
    } catch (e) {
      // Non-fatal frame capture hiccup
    } finally {
      isCanvasFallbackDecoding = false;
    }
  }

  function handleCameraDetection(decodedText, payloadType = null, classification = null) {
    if (!isDetecting) return;

    // Duplicate prevention and 3-second cooldown
    const now = Date.now();
    if (decodedText === lastDecodedPayload && (now - lastDecodedTime) < DUPLICATE_COOLDOWN_MS) {
      return;
    }
    lastDecodedPayload = decodedText;
    lastDecodedTime = now;

    // Immediately pause detection loop to prevent rapid-fire redundant scans
    isDetecting = false;

    // Viewfinder visual and tactile feedback
    if (cameraReticle) cameraReticle.classList.add('detected');
    if (reticleInstruction) reticleInstruction.textContent = 'QR Code Detected!';
    updateCameraStatus('paused', 'Decoded');

    if (navigator.vibrate) {
      try { navigator.vibrate(80); } catch (e) {}
    }

    if (btnCameraScanAgain) btnCameraScanAgain.style.display = 'inline-flex';

    // If payload classification is missing, fetch classification from backend
    if (!classification) {
      fetch('/api/decode-qr', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: decodedText, scan_type: 'camera' })
      }).then(r => r.json()).then(resData => {
        if (resData.success) {
          displayDecodedResult(resData, 'camera');
        } else {
          displayDecodedResult({
            decoded_content: decodedText,
            payload_type: payloadType || 'Payload',
            classification: null
          }, 'camera');
        }
      }).catch(() => {
        displayDecodedResult({
          decoded_content: decodedText,
          payload_type: payloadType || 'Payload',
          classification: null
        }, 'camera');
      });
    } else {
      displayDecodedResult({
        decoded_content: decodedText,
        payload_type: payloadType || classification.display_name || 'Payload',
        classification: classification
      }, 'camera');
    }
  }

  function resumeCameraScanning() {
    clearError(cameraFeedback);
    if (cameraReticle) cameraReticle.classList.remove('detected');
    if (reticleInstruction) reticleInstruction.textContent = 'Point camera at a QR code to decode';
    if (btnCameraScanAgain) btnCameraScanAgain.style.display = 'none';
    updateCameraStatus('active', 'Scanning Live');
    isDetecting = true;

    if (!isCameraActive) {
      startCamera();
    }
  }

  async function switchCamera() {
    if (availableVideoDevices.length <= 1) return;
    currentDeviceIndex = (currentDeviceIndex + 1) % availableVideoDevices.length;
    const selected = availableVideoDevices[currentDeviceIndex];
    if (cameraDeviceSelect) cameraDeviceSelect.value = selected.deviceId;
    await startCamera(selected.deviceId);
  }

  // Camera Event Listeners
  if (btnStartCamera) {
    btnStartCamera.addEventListener('click', (e) => {
      e.preventDefault();
      startCamera();
    });
  }

  if (btnStopCamera) {
    btnStopCamera.addEventListener('click', (e) => {
      e.preventDefault();
      stopCamera();
    });
  }

  if (btnCameraScanAgain) {
    btnCameraScanAgain.addEventListener('click', (e) => {
      e.preventDefault();
      resumeCameraScanning();
    });
  }

  if (btnSwitchCamera) {
    btnSwitchCamera.addEventListener('click', (e) => {
      e.preventDefault();
      switchCamera();
    });
  }

  if (cameraDeviceSelect) {
    cameraDeviceSelect.addEventListener('change', (e) => {
      const devId = e.target.value;
      startCamera(devId || null);
    });
  }

  if (btnUseCamera) {
    btnUseCamera.addEventListener('click', (e) => {
      e.preventDefault();
      activateTab(tabCamera, panelCamera);
      startCamera();
    });
  }

  // Hardware lifecycle cleanup (stops tracks when tab is hidden or page unloaded)
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden' && isCameraActive) {
      stopCamera();
    }
  });

  window.addEventListener('pagehide', () => {
    stopCamera();
  });

  window.addEventListener('beforeunload', () => {
    stopCamera();
  });

  // Live QR Decoding via AJAX (POST /api/decode-qr)
  if (qrUploadForm && btnScanFile) {
    qrUploadForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      clearError(uploadFeedback);
      if (resultsStagingArea) resultsStagingArea.style.display = 'none';
      if (urlAnalysisResultsPanel) urlAnalysisResultsPanel.style.display = 'none';
      if (payloadContextNotice) payloadContextNotice.style.display = 'none';

      if (!fileInput.files || fileInput.files.length === 0) {
        showError(uploadFeedback, 'Please select or drag a valid QR image before decoding.');
        return;
      }

      const file = fileInput.files[0];
      if (!isAllowedFile(file)) {
        showError(uploadFeedback, 'Unsupported file format. Please select a PNG, JPG, JPEG, or WebP image.');
        return;
      }

      if (file.size > MAX_FILE_SIZE) {
        showError(uploadFeedback, `File exceeds the 5 MB limit (${formatBytes(file.size)}).`);
        return;
      }

      const formData = new FormData();
      formData.append('qr_file', file);

      btnScanFile.setAttribute('disabled', 'true');
      if (btnScanText) btnScanText.textContent = 'Decoding matrix...';

      try {
        const response = await fetch('/api/decode-qr', {
          method: 'POST',
          body: formData
        });

        const data = await response.json();

        if (response.ok && data.success) {
          displayDecodedResult(data, 'upload');
        } else {
          showError(uploadFeedback, data.message || 'Unable to decode this QR code. Try a clearer image.');
        }
      } catch (err) {
        showError(uploadFeedback, 'Network or server error while connecting to the decoder. Please try again.');
      } finally {
        btnScanFile.removeAttribute('disabled');
        if (btnScanText) btnScanText.textContent = 'Decode QR Code';
      }
    });
  }

  /**
   * Performs static URL heuristic analysis via POST /api/analyze-url
   * Strictly in-memory analysis; never fetches or executes targetUrl.
   */
  async function performUrlAnalysis(targetUrl, scanType = 'upload') {
    if (!targetUrl) return;

    if (btnAnalyzeDecodedUrl) btnAnalyzeDecodedUrl.setAttribute('disabled', 'true');
    if (btnAnalyzeText) btnAnalyzeText.textContent = 'Analyzing link...';

    try {
      const response = await fetch('/api/analyze-url', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url: targetUrl, scan_type: scanType })
      });

      const data = await response.json();

      if (response.ok && data.valid) {
        activeScanResult = data;
        renderAnalysisFindings(data);
      } else {
        renderAnalysisError(data.message || 'Unable to analyze URL.');
      }
    } catch (err) {
      renderAnalysisError('Connection error while performing URL analysis.');
    } finally {
      if (btnAnalyzeDecodedUrl) btnAnalyzeDecodedUrl.removeAttribute('disabled');
      if (btnAnalyzeText) btnAnalyzeText.textContent = 'Re-analyze URL';
    }
  }

  // Threat Intelligence Elements
  const btnCheckReputation = document.getElementById('btnCheckReputation');
  const btnReputationText = document.getElementById('btnReputationText');
  const reputationFeedbackText = document.getElementById('reputationFeedbackText');
  const threatReputationBadge = document.getElementById('threatReputationBadge');
  const threatResultDetails = document.getElementById('threatResultDetails');
  const threatProviderName = document.getElementById('threatProviderName');
  const threatCheckedTimestamp = document.getElementById('threatCheckedTimestamp');
  const threatSummaryMessage = document.getElementById('threatSummaryMessage');
  const threatCategoriesBox = document.getElementById('threatCategoriesBox');
  const threatCategoriesList = document.getElementById('threatCategoriesList');
  const threatLimitationsNotice = document.getElementById('threatLimitationsNotice');
  const auditThreatStatus = document.getElementById('auditThreatStatus');

  let activeVerifiedUrl = null;

  /**
   * Check external threat intelligence reputation upon explicit user click
   */
  async function performThreatIntelligenceLookup(targetUrl) {
    if (!targetUrl) return;

    if (btnCheckReputation) {
      btnCheckReputation.setAttribute('disabled', 'true');
    }
    if (btnReputationText) {
      btnReputationText.textContent = 'Querying Threat Feed...';
    }
    if (reputationFeedbackText) {
      reputationFeedbackText.textContent = 'Connecting to external provider securely...';
    }

    try {
      const response = await fetch('/api/check-reputation', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          url: targetUrl,
          user_consent: true
        })
      });

      const data = await response.json();
      const rep = data.reputation_result || {};

      renderThreatReputationResult(rep);

    } catch (err) {
      renderThreatReputationResult({
        provider: 'Google Safe Browsing',
        status: 'provider_error',
        reputation: 'unknown',
        threat_categories: [],
        summary: 'Network error communicating with threat intelligence service.',
        checked_at: new Date().toISOString(),
        limitations: 'Technical network failure. Could not contact the external provider.'
      });
    } finally {
      if (btnCheckReputation) {
        btnCheckReputation.removeAttribute('disabled');
      }
      if (btnReputationText) {
        btnReputationText.textContent = 'Re-check Reputation';
      }
    }
  }

  function renderThreatReputationResult(rep) {
    if (!threatResultDetails) return;

    const status = rep.status || 'unknown';
    const reputation = rep.reputation || 'unknown';
    const provider = rep.provider || 'Google Safe Browsing';
    const summary = rep.summary || '';
    const checkedAt = rep.checked_at;
    const categories = rep.threat_categories || [];
    const limitations = rep.limitations || '';

    // Update Badge
    if (threatReputationBadge) {
      if (reputation === 'malicious') {
        threatReputationBadge.className = 'card-badge risk-high';
        threatReputationBadge.textContent = 'KNOWN THREAT DETECTED';
      } else if (reputation === 'no_known_threat_detected') {
        threatReputationBadge.className = 'card-badge risk-lower';
        threatReputationBadge.textContent = 'No Known Threats Listed';
      } else if (status === 'not_configured') {
        threatReputationBadge.className = 'card-badge badge-planned';
        threatReputationBadge.textContent = 'Not Configured (Key Required)';
      } else if (status === 'skipped_sensitive_url') {
        threatReputationBadge.className = 'card-badge risk-suspicious';
        threatReputationBadge.textContent = 'Skipped (Privacy Guard)';
      } else if (status === 'rate_limited') {
        threatReputationBadge.className = 'card-badge badge-planned';
        threatReputationBadge.textContent = 'Rate Limited';
      } else if (status === 'timeout') {
        threatReputationBadge.className = 'card-badge badge-planned';
        threatReputationBadge.textContent = 'Lookup Timed Out';
      } else {
        threatReputationBadge.className = 'card-badge badge-planned';
        threatReputationBadge.textContent = 'Lookup Unavailable';
      }
    }

    // Update Result Box Styling
    if (reputation === 'malicious') {
      threatResultDetails.style.backgroundColor = '#FEF2F2';
      threatResultDetails.style.borderColor = '#F87171';
      if (threatSummaryMessage) {
        threatSummaryMessage.style.color = '#991B1B';
      }
    } else if (reputation === 'no_known_threat_detected') {
      threatResultDetails.style.backgroundColor = '#F0FDF4';
      threatResultDetails.style.borderColor = '#86EFAC';
      if (threatSummaryMessage) {
        threatSummaryMessage.style.color = '#166534';
      }
    } else {
      threatResultDetails.style.backgroundColor = 'var(--color-surface-muted)';
      threatResultDetails.style.borderColor = 'var(--color-border)';
      if (threatSummaryMessage) {
        threatSummaryMessage.style.color = 'var(--color-text-primary)';
      }
    }

    // Populate Fields
    if (threatProviderName) {
      threatProviderName.textContent = `Provider: ${provider}`;
    }
    if (threatCheckedTimestamp) {
      threatCheckedTimestamp.textContent = checkedAt ? `Checked: ${new Date(checkedAt).toLocaleTimeString()}` : '';
    }
    if (threatSummaryMessage) {
      threatSummaryMessage.textContent = summary;
    }

    // Categories
    if (threatCategoriesBox && threatCategoriesList) {
      if (categories.length > 0) {
        threatCategoriesBox.style.display = 'block';
        threatCategoriesList.innerHTML = '';
        categories.forEach(cat => {
          const catSpan = document.createElement('span');
          catSpan.className = 'card-badge risk-high';
          catSpan.style.marginRight = '0.35rem';
          catSpan.style.fontSize = '0.75rem';
          catSpan.textContent = cat;
          threatCategoriesList.appendChild(catSpan);
        });
      } else {
        threatCategoriesBox.style.display = 'none';
      }
    }

    if (threatLimitationsNotice) {
      threatLimitationsNotice.textContent = limitations;
    }

    if (reputationFeedbackText) {
      reputationFeedbackText.textContent = `Lookup completed (${status}).`;
    }

    if (auditThreatStatus) {
      if (reputation === 'malicious') {
        auditThreatStatus.textContent = '⚠ Known Threat Found';
        auditThreatStatus.style.color = 'var(--color-risk-high)';
      } else if (reputation === 'no_known_threat_detected') {
        auditThreatStatus.textContent = '✓ No Threat Listed';
        auditThreatStatus.style.color = 'var(--color-risk-lower)';
      } else {
        auditThreatStatus.textContent = `• ${status}`;
        auditThreatStatus.style.color = 'var(--color-text-secondary)';
      }
    }

    threatResultDetails.style.display = 'block';
  }

  // Bind reputation check button
  if (btnCheckReputation) {
    btnCheckReputation.addEventListener('click', (e) => {
      e.preventDefault();
      if (activeVerifiedUrl) {
        performThreatIntelligenceLookup(activeVerifiedUrl);
      }
    });
  }

  // Elements: Safe Redirect Inspector (Prompt 12)
  const btnInspectRedirects = document.getElementById('btnInspectRedirects');
  const btnRedirectText = document.getElementById('btnRedirectText');
  const redirectFeedbackText = document.getElementById('redirectFeedbackText');
  const redirectStatusBadge = document.getElementById('redirectStatusBadge');
  const redirectResultDetails = document.getElementById('redirectResultDetails');
  const redirectSummaryHeader = document.getElementById('redirectSummaryHeader');
  const redirectHopsList = document.getElementById('redirectHopsList');
  const redirectFindingsBox = document.getElementById('redirectFindingsBox');
  const redirectFindingsList = document.getElementById('redirectFindingsList');
  const redirectLimitationsNotice = document.getElementById('redirectLimitationsNotice');

  async function performRedirectInspection(targetUrl) {
    if (!targetUrl) return;

    if (btnInspectRedirects) {
      btnInspectRedirects.setAttribute('disabled', 'true');
    }
    if (btnRedirectText) {
      btnRedirectText.textContent = 'Tracing Hops...';
    }
    if (redirectFeedbackText) {
      redirectFeedbackText.textContent = 'Validating SSRF safety and inspecting hops...';
    }

    try {
      const response = await fetch('/api/inspect-redirects', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          url: targetUrl,
          user_consent: true
        })
      });

      const data = await response.json();
      renderRedirectResults(data.redirect_result || {});

    } catch (err) {
      renderRedirectResults({
        status: 'connection_error',
        hops: [],
        redirect_count: 0,
        summary: 'Network error communicating with redirect inspection service.',
        findings: [{
          title: 'Inspection Error',
          severity: 'info',
          explanation: 'Could not contact the local inspection endpoint.',
          evidence: String(err)
        }],
        limitations: 'Technical network failure.'
      });
    } finally {
      if (btnInspectRedirects) {
        btnInspectRedirects.removeAttribute('disabled');
      }
      if (btnRedirectText) {
        btnRedirectText.textContent = 'Re-inspect Redirects';
      }
    }
  }

  function renderRedirectResults(res) {
    if (!redirectResultDetails) return;

    const status = res.status || 'unknown';
    const hops = res.hops || [];
    const count = res.redirect_count || 0;
    const summary = res.summary || '';
    const findings = res.findings || [];
    const limitations = res.limitations || '';
    const checkedAt = res.checked_at;

    // Update Badge
    if (redirectStatusBadge) {
      if (status === 'blocked') {
        redirectStatusBadge.className = 'card-badge risk-high';
        redirectStatusBadge.textContent = 'BLOCKED (SSRF Guard)';
      } else if (status === 'skipped_sensitive_url') {
        redirectStatusBadge.className = 'card-badge risk-suspicious';
        redirectStatusBadge.textContent = 'Skipped (Privacy Guard)';
      } else if (count > 0) {
        redirectStatusBadge.className = 'card-badge risk-suspicious';
        redirectStatusBadge.textContent = `${count} Redirect Hop${count === 1 ? '' : 's'}`;
      } else if (status === 'completed') {
        redirectStatusBadge.className = 'card-badge risk-lower';
        redirectStatusBadge.textContent = 'Direct (0 Redirects)';
      } else {
        redirectStatusBadge.className = 'card-badge badge-planned';
        redirectStatusBadge.textContent = status.toUpperCase();
      }
    }

    if (redirectSummaryHeader) {
      redirectSummaryHeader.textContent = summary;
    }

    const timeEl = document.getElementById('redirectCheckedTimestamp');
    if (timeEl) {
      timeEl.textContent = checkedAt ? `Checked: ${new Date(checkedAt).toLocaleTimeString()}` : '';
    }

    // Render Hops Step List
    if (redirectHopsList) {
      redirectHopsList.innerHTML = '';
      if (hops.length === 0) {
        const noHops = document.createElement('div');
        noHops.style.fontSize = '0.85rem';
        noHops.style.color = 'var(--color-text-secondary)';
        noHops.textContent = 'No HTTP redirect hops were recorded.';
        redirectHopsList.appendChild(noHops);
      } else {
        hops.forEach((h, idx) => {
          const hopCard = document.createElement('div');
          hopCard.className = 'card';
          hopCard.style.padding = 'var(--space-xs) var(--space-sm)';
          hopCard.style.backgroundColor = h.is_downgrade ? '#FEF2F2' : (h.is_cross_domain ? '#FFFBEB' : 'var(--color-surface-muted)');
          hopCard.style.fontSize = '0.85rem';
          hopCard.style.display = 'flex';
          hopCard.style.justifyContent = 'space-between';
          hopCard.style.alignItems = 'center';
          hopCard.style.gap = '0.5rem';
          hopCard.style.flexWrap = 'wrap';

          const left = document.createElement('div');
          left.style.display = 'flex';
          left.style.alignItems = 'center';
          left.style.gap = '0.4rem';

          const hopNum = document.createElement('span');
          hopNum.style.fontWeight = '700';
          hopNum.style.color = 'var(--color-text-secondary)';
          hopNum.textContent = `Hop #${h.hop_number || (idx + 1)}:`;

          const codeBadge = document.createElement('span');
          codeBadge.className = 'card-badge';
          codeBadge.style.fontSize = '0.75rem';
          codeBadge.style.padding = '0.15rem 0.4rem';
          codeBadge.textContent = `HTTP ${h.status_code || 200}`;

          const destText = document.createElement('span');
          destText.style.fontWeight = '600';
          destText.textContent = h.destination_display || h.destination_host;

          left.appendChild(hopNum);
          left.appendChild(codeBadge);
          left.appendChild(destText);

          const right = document.createElement('div');
          if (h.is_downgrade) {
            const downTag = document.createElement('span');
            downTag.className = 'card-badge risk-high';
            downTag.style.fontSize = '0.7rem';
            downTag.textContent = 'HTTPS \u2192 HTTP';
            right.appendChild(downTag);
          } else if (h.is_cross_domain) {
            const crossTag = document.createElement('span');
            crossTag.className = 'card-badge risk-suspicious';
            crossTag.style.fontSize = '0.7rem';
            crossTag.textContent = 'Cross-Domain';
            right.appendChild(crossTag);
          }

          hopCard.appendChild(left);
          hopCard.appendChild(right);
          redirectHopsList.appendChild(hopCard);
        });
      }
    }

    // Render Findings List
    if (redirectFindingsBox && redirectFindingsList) {
      redirectFindingsList.innerHTML = '';
      if (findings.length > 0) {
        findings.forEach(f => {
          const fCard = document.createElement('div');
          fCard.style.fontSize = '0.825rem';
          fCard.style.padding = '0.35rem 0.5rem';
          fCard.style.borderRadius = 'var(--radius-sm)';
          fCard.style.backgroundColor = f.severity === 'high' ? '#FEF2F2' : (f.severity === 'medium' ? '#FFFBEB' : 'var(--color-surface-muted)');
          fCard.style.color = f.severity === 'high' ? '#991B1B' : (f.severity === 'medium' ? '#92400E' : 'var(--color-text-primary)');
          fCard.innerHTML = `<strong>${f.title}:</strong> ${f.explanation}`;
          redirectFindingsList.appendChild(fCard);
        });
        redirectFindingsBox.style.display = 'block';
      } else {
        redirectFindingsBox.style.display = 'none';
      }
    }

    if (redirectLimitationsNotice) {
      redirectLimitationsNotice.textContent = limitations;
    }

    if (redirectFeedbackText) {
      redirectFeedbackText.textContent = `Inspection complete (${status}).`;
    }

    redirectResultDetails.style.display = 'block';
  }

  // Bind Redirect button
  if (btnInspectRedirects) {
    btnInspectRedirects.addEventListener('click', (e) => {
      e.preventDefault();
      if (activeVerifiedUrl) {
        performRedirectInspection(activeVerifiedUrl);
      }
    });
  }

  function renderAnalysisFindings(data) {
    if (!urlAnalysisResultsPanel || !indicatorsList) return;

    indicatorsList.innerHTML = '';

    // Cache the verified URL for user-demanded reputation lookup
    activeVerifiedUrl = (data.parsed_url && (data.parsed_url.scheme + '://' + data.parsed_url.hostname + (data.parsed_url.port ? ':' + data.parsed_url.port : '') + data.parsed_url.path)) || activeDecodedPayload;

    // Reset Threat Intelligence state on new analysis
    if (threatReputationBadge) {
      threatReputationBadge.className = 'card-badge badge-planned';
      threatReputationBadge.textContent = 'Not Queried';
    }
    if (threatResultDetails) {
      threatResultDetails.style.display = 'none';
    }
    if (reputationFeedbackText) {
      reputationFeedbackText.textContent = 'Optional external lookup • Requires server-side API key';
    }
    if (btnCheckReputation) {
      btnCheckReputation.removeAttribute('disabled');
    }
    if (btnReputationText) {
      btnReputationText.textContent = 'Check URL Reputation';
    }

    // Reset Redirect Inspector state on new analysis
    if (redirectStatusBadge) {
      redirectStatusBadge.className = 'card-badge badge-planned';
      redirectStatusBadge.textContent = 'Not Inspected';
    }
    if (redirectResultDetails) {
      redirectResultDetails.style.display = 'none';
    }
    if (redirectFeedbackText) {
      redirectFeedbackText.textContent = 'Optional external trace • SSRF-guarded manual stepping';
    }
    if (btnInspectRedirects) {
      btnInspectRedirects.removeAttribute('disabled');
    }
    if (btnRedirectText) {
      btnRedirectText.textContent = 'Inspect Redirects';
    }

    const riskAssessment = data.risk_assessment || {};
    const score = riskAssessment.score !== undefined && riskAssessment.score !== null ? riskAssessment.score : '--';
    const riskLevel = riskAssessment.risk_level || 'inconclusive';
    const summary = riskAssessment.summary || '';
    const contributing = riskAssessment.contributing_indicators || data.indicators || [];
    const groupedRecs = riskAssessment.grouped_recommendations || {};
    const whatToCheck = groupedRecs.what_to_check || [];
    const whatToAvoid = groupedRecs.what_to_avoid || [];
    const nextStep = groupedRecs.recommended_next_step || 'Exercise ordinary web caution.';
    const limitations = riskAssessment.limitations || '';

    // Update Header Status
    if (reportStatusSummary) {
      reportStatusSummary.textContent = `Analysis Complete (${riskLevel.toUpperCase()})`;
    }
    if (reportTimestamp && data.timestamp) {
      try {
        reportTimestamp.textContent = new Date(data.timestamp).toLocaleTimeString();
      } catch (e) {}
    }

    // 1. Update Score Circle
    const scoreValEl = document.getElementById('riskScoreVal');
    const scoreCircleEl = document.getElementById('riskScoreCircle');
    if (scoreValEl) scoreValEl.textContent = score;

    let circleColor = 'var(--color-risk-lower)';
    let circleBg = 'var(--color-risk-lower-bg)';
    let badgeClass = 'risk-lower';
    let badgeText = 'Low Risk';

    if (riskLevel === 'critical') {
      circleColor = 'var(--color-risk-high)';
      circleBg = 'var(--color-risk-high-bg)';
      badgeClass = 'risk-high';
      badgeText = 'Critical Risk';
    } else if (riskLevel === 'high') {
      circleColor = 'var(--color-risk-high)';
      circleBg = 'var(--color-risk-high-bg)';
      badgeClass = 'risk-high';
      badgeText = 'High Risk';
    } else if (riskLevel === 'medium') {
      circleColor = 'var(--color-risk-suspicious)';
      circleBg = 'var(--color-risk-suspicious-bg)';
      badgeClass = 'risk-suspicious';
      badgeText = 'Medium Risk';
    } else if (riskLevel === 'inconclusive') {
      circleColor = 'var(--color-risk-inconclusive)';
      circleBg = 'var(--color-risk-inconclusive-bg)';
      badgeClass = 'badge-planned';
      badgeText = 'Inconclusive';
    }

    if (scoreCircleEl) {
      scoreCircleEl.style.borderColor = circleColor;
      scoreCircleEl.style.backgroundColor = circleBg;
    }

    const categoryBadgeEl = document.getElementById('riskCategoryBadge');
    if (categoryBadgeEl) {
      categoryBadgeEl.className = `card-badge ${badgeClass}`;
      categoryBadgeEl.textContent = badgeText;
    }

    const countBadgeEl = document.getElementById('indicatorsCountBadge');
    const activeIndicators = contributing.filter(i => (i.weight === undefined || i.weight > 0));
    if (countBadgeEl) {
      countBadgeEl.textContent = `${activeIndicators.length} Weighted Indicator${activeIndicators.length === 1 ? '' : 's'}`;
      countBadgeEl.className = activeIndicators.length > 0 ? 'card-badge badge-planned' : 'card-badge badge-implemented';
    }

    // Modular Intelligence Telemetry
    const detectionEngine = data.detection_engine || {};
    const methodBadge = document.getElementById('engineMethodBadge');
    if (methodBadge) {
      const rawMethod = detectionEngine.analysis_method || 'heuristic_rules';
      methodBadge.textContent = rawMethod === 'hybrid_ensemble' ? 'Hybrid Ensemble' :
        (rawMethod === 'heuristic_plus_threat_feed' ? 'Heuristic + Threat Feed' : 'Heuristic Rules');
    }

    const confBadge = document.getElementById('engineConfidenceBadge');
    if (confBadge) {
      const confLabel = (detectionEngine.confidence_label || 'medium').toUpperCase();
      confBadge.textContent = `Confidence: ${confLabel}`;
    }

    // Telemetry Details Block
    const telEngine = document.getElementById('telemetryEngineMethod');
    if (telEngine) telEngine.textContent = detectionEngine.analysis_method || 'heuristic_rules';

    const telConf = document.getElementById('telemetryConfidence');
    if (telConf) telConf.textContent = (detectionEngine.confidence_label || 'medium').toUpperCase();

    const telML = document.getElementById('telemetryMLStatus');
    if (telML) {
      const ml = detectionEngine.ml_assessment || {};
      telML.textContent = ml.status === 'completed' ? ml.message : 'Unavailable (Rule-Based Fallback)';
    }

    const telSrc = document.getElementById('telemetrySources');
    if (telSrc) {
      telSrc.textContent = (detectionEngine.evidence_sources || ['local_heuristics', 'payload_classifier']).join(', ');
    }

    const featGrid = document.getElementById('telemetryFeaturesGrid');
    if (featGrid) {
      featGrid.innerHTML = '';
      const feats = detectionEngine.extracted_features || {};
      const displayKeys = [
        ['URL Length', feats.url_length],
        ['Host Length', feats.hostname_length],
        ['Subdomains', feats.subdomain_depth],
        ['Path Entropy', feats.path_entropy ? `${feats.path_entropy} H` : '0.0'],
        ['Query Entropy', feats.query_entropy ? `${feats.query_entropy} H` : '0.0'],
        ['Digit Ratio', feats.digit_ratio_hostname],
        ['Punycode', feats.is_punycode ? 'Yes' : 'No'],
        ['Raw IP Host', feats.is_ip_host ? 'Yes' : 'No'],
        ['Redirect Params', feats.has_redirect_param ? 'Detected' : 'None'],
        ['Userinfo Embedded', feats.has_userinfo ? 'Detected' : 'None']
      ];
      displayKeys.forEach(([label, val]) => {
        if (val !== undefined) {
          const div = document.createElement('div');
          div.innerHTML = `<span style="color:var(--color-text-muted);">${label}:</span> <strong>${val}</strong>`;
          featGrid.appendChild(div);
        }
      });
    }

    // 2. Summary Text
    const summaryEl = document.getElementById('riskSummaryText');
    if (summaryEl) {
      summaryEl.textContent = summary;
    }

    // 3. Render Contributing Indicators
    if (contributing.length === 0) {
      const emptyCard = document.createElement('div');
      emptyCard.className = 'alert-box';
      emptyCard.style.borderLeftColor = 'var(--color-risk-lower)';
      emptyCard.style.fontSize = '0.875rem';
      
      const strong = document.createElement('strong');
      strong.textContent = 'Clean Static Structure: ';
      const span = document.createElement('span');
      span.textContent = 'No configured suspicious patterns were detected by these checks. This does not guarantee that the destination is safe.';
      
      emptyCard.appendChild(strong);
      emptyCard.appendChild(span);
      indicatorsList.appendChild(emptyCard);
    } else {
      contributing.forEach((ind) => {
        const item = document.createElement('details');
        item.className = 'card';
        item.style.padding = 'var(--space-md)';
        item.style.backgroundColor = '#FFFFFF';

        const summarySummary = document.createElement('summary');
        summarySummary.style.cursor = 'pointer';
        summarySummary.style.fontWeight = '600';
        summarySummary.style.display = 'flex';
        summarySummary.style.justifyContent = 'space-between';
        summarySummary.style.alignItems = 'center';
        summarySummary.style.gap = '0.5rem';

        const leftBox = document.createElement('div');
        leftBox.style.display = 'flex';
        leftBox.style.alignItems = 'center';
        leftBox.style.gap = '0.6rem';

        const sev = (ind.severity || 'info').toLowerCase();
        const tag = document.createElement('span');
        tag.className = `ind-tag ind-tag-${sev === 'high' ? 'suspicious' : (sev === 'medium' ? 'suspicious' : 'lower')}`;
        tag.textContent = ind.weight !== undefined ? `+${ind.weight} PTS` : sev.toUpperCase();

        const titleSpan = document.createElement('span');
        titleSpan.textContent = ind.title;

        leftBox.appendChild(tag);
        leftBox.appendChild(titleSpan);

        const toggleHint = document.createElement('span');
        toggleHint.textContent = 'Evidence \u25BE';
        toggleHint.style.fontSize = '0.75rem';
        toggleHint.style.color = 'var(--color-text-secondary)';

        summarySummary.appendChild(leftBox);
        summarySummary.appendChild(toggleHint);
        item.appendChild(summarySummary);

        const detailsBody = document.createElement('div');
        detailsBody.style.marginTop = 'var(--space-sm)';
        detailsBody.style.fontSize = '0.875rem';
        detailsBody.style.color = 'var(--color-text-secondary)';

        const explP = document.createElement('p');
        explP.textContent = ind.explanation;
        explP.style.marginBottom = '0.4rem';
        detailsBody.appendChild(explP);

        if (ind.evidence) {
          const evidP = document.createElement('div');
          evidP.style.fontFamily = 'var(--font-mono)';
          evidP.style.fontSize = '0.8rem';
          evidP.style.backgroundColor = 'var(--color-surface-muted)';
          evidP.style.padding = '0.4rem 0.6rem';
          evidP.style.borderRadius = 'var(--radius-sm)';
          evidP.textContent = `Evidence: ${ind.evidence}`;
          detailsBody.appendChild(evidP);
        }

        item.appendChild(detailsBody);
        indicatorsList.appendChild(item);
      });
    }

    // 4. Render Grouped Recommendations
    const recsCheckEl = document.getElementById('recsWhatToCheck');
    const recsAvoidEl = document.getElementById('recsWhatToAvoid');
    const recsNextEl = document.getElementById('recsNextStep');

    if (recsCheckEl) {
      recsCheckEl.innerHTML = '';
      whatToCheck.forEach(rec => {
        const li = document.createElement('li');
        li.textContent = `\u2022 ${rec}`;
        recsCheckEl.appendChild(li);
      });
    }

    if (recsAvoidEl) {
      recsAvoidEl.innerHTML = '';
      whatToAvoid.forEach(rec => {
        const li = document.createElement('li');
        li.textContent = `\u2022 ${rec}`;
        recsAvoidEl.appendChild(li);
      });
    }

    if (recsNextEl) {
      recsNextEl.textContent = nextStep;
    }

    // 5. Update Limitations Notice
    const limitationsEl = document.getElementById('limitationsText');
    if (limitationsEl && limitations) {
      limitationsEl.innerHTML = `<strong>Assessment Limitations:</strong> ${limitations}`;
    }

    urlAnalysisResultsPanel.style.display = 'block';
    urlAnalysisResultsPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function renderAnalysisError(errorMsg) {
    if (!urlAnalysisResultsPanel || !indicatorsList) return;
    indicatorsList.innerHTML = '';
    
    const errBox = document.createElement('div');
    errBox.className = 'alert-box';
    errBox.style.borderLeftColor = 'var(--color-risk-high)';
    errBox.style.fontSize = '0.875rem';
    errBox.textContent = `Analysis Notice: ${errorMsg}`;
    
    indicatorsList.appendChild(errBox);
    urlAnalysisResultsPanel.style.display = 'block';
  }

  // Bind click on Analyze URL button
  if (btnAnalyzeDecodedUrl) {
    btnAnalyzeDecodedUrl.addEventListener('click', (e) => {
      e.preventDefault();
      if (activeDecodedPayload) {
        performUrlAnalysis(activeDecodedPayload, activeScanSource || 'upload');
      }
    });
  }

  // Manual URL Inspection Handler
  if (btnScanUrl && manualUrlInput && manualUrlForm) {
    manualUrlForm.addEventListener('submit', (e) => {
      clearError(urlFeedback);
      const rawUrl = manualUrlInput.value.trim();

      if (!rawUrl) {
        e.preventDefault();
        showError(urlFeedback, 'Please enter a web address to inspect.');
        return;
      }

      const lower = rawUrl.toLowerCase();
      if (lower.startsWith('javascript:') || lower.startsWith('data:') || lower.startsWith('file:') || lower.startsWith('vbscript:') || lower.startsWith('blob:')) {
        e.preventDefault();
        showError(urlFeedback, 'Disallowed protocol. Only standard HTTP and HTTPS web addresses can be inspected.');
        return;
      }

      try {
        let testUrl = rawUrl;
        if (!/^https?:\/\//i.test(testUrl)) {
          testUrl = 'http://' + testUrl;
        }
        const parsed = new URL(testUrl);

        if (!['http:', 'https:'].includes(parsed.protocol)) {
          e.preventDefault();
          showError(urlFeedback, 'Unsupported protocol. Only HTTP and HTTPS URLs are accepted.');
          return;
        }

        if (!parsed.hostname || (parsed.hostname.indexOf('.') === -1 && parsed.hostname !== 'localhost')) {
          e.preventDefault();
          showError(urlFeedback, 'Please provide a complete hostname (e.g., example.com or sub.example.com).');
          return;
        }
      } catch (err) {
        e.preventDefault();
        showError(urlFeedback, 'Invalid URL format. Please check the address structure (e.g., https://example.com).');
      }
    });
  }
});
