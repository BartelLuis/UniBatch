'use strict';

// Local modal controls. All labels and entered values stay as text.
(() => {
  const queue = [];
  let active = null;
  let sequence = 0;

  function node(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = String(text);
    return element;
  }

  function action(label, className, handler) {
    const button = node('button', className, label);
    button.type = 'button';
    button.addEventListener('click', handler);
    return button;
  }

  function mark(danger) {
    const namespace = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(namespace, 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('width', '22');
    svg.setAttribute('height', '22');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '1.7');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    svg.setAttribute('aria-hidden', 'true');
    const path = document.createElementNS(namespace, 'path');
    path.setAttribute('d', danger
      ? 'M10.3 4.1 2.8 17.3A2 2 0 0 0 4.5 20h15a2 2 0 0 0 1.7-2.7L13.7 4.1a2 2 0 0 0-3.4 0ZM12 9v4m0 3h.01'
      : 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Zm0 8v5m0-8h.01');
    svg.append(path);
    return svg;
  }

  function restoreFocus(target) {
    if (target && target.isConnected && !target.disabled &&
        !target.closest('[inert], [hidden]') && typeof target.focus === 'function') {
      target.focus({ preventScroll: true });
    }
  }

  function advance() {
    if (active || !queue.length) return;
    if (!document.body) {
      document.addEventListener('DOMContentLoaded', advance, { once: true });
      return;
    }

    const request = queue.shift();
    active = request;
    const options = request.options;
    const isPrompt = request.kind === 'prompt';
    const danger = !isPrompt && Boolean(options.danger);
    const id = 'ui-dialog-' + (++sequence);
    const dialog = node('dialog', 'app-dialog' + (danger ? ' is-danger' : ''));
    dialog.setAttribute('aria-labelledby', id + '-title');
    dialog.setAttribute('aria-describedby', id + '-message');

    const form = node('form', 'dialog-form');
    const header = node('div', 'dialog-header');
    const icon = node('span', 'dialog-icon' + (danger ? ' is-danger' : ''));
    icon.append(mark(danger));
    const copy = node('div', 'dialog-copy');
    const title = node('h2', '', options.title || (isPrompt ? 'Angabe bearbeiten' : 'Aktion bestätigen'));
    title.id = id + '-title';
    const message = node('p', '', options.message || '');
    message.id = id + '-message';
    copy.append(title, message);

    let finished = false;
    let field = null;
    const cancelledValue = isPrompt ? null : false;

    function finish(value) {
      if (finished) return;
      finished = true;
      if (dialog.open) dialog.close();
      dialog.remove();
      active = null;
      restoreFocus(request.focusTarget);
      request.resolve(value);
      // Allow the caller to finish its continuation before another modal opens.
      queueMicrotask(advance);
    }

    const close = action('×', 'dialog-close', () => finish(cancelledValue));
    close.setAttribute('aria-label', 'Dialog schließen');
    close.setAttribute('title', 'Schließen');
    header.append(icon, copy, close);

    const body = node('div', 'dialog-body');
    if (isPrompt) {
      const label = node('label', 'dialog-field', options.label || 'Wert');
      label.htmlFor = id + '-input';
      field = node(options.multiline ? 'textarea' : 'input', 'dialog-input');
      field.id = id + '-input';
      field.name = 'value';
      field.required = options.required !== false;
      field.value = options.value === undefined || options.value === null ? '' : String(options.value);
      field.placeholder = options.placeholder === undefined ? '' : String(options.placeholder);
      field.setAttribute('autocomplete', 'off');
      field.setAttribute('aria-describedby', message.id);
      if (options.multiline) field.rows = 4;
      else field.type = 'text';
      field.addEventListener('input', () => field.setCustomValidity(''));
      label.append(field);
      body.append(label);
    }

    const actions = node('div', 'dialog-actions');
    const cancel = action('Abbrechen', '', () => finish(cancelledValue));
    const confirm = node('button', danger ? 'danger-confirm' : 'primary',
      options.confirmLabel || (isPrompt ? 'Speichern' : 'Bestätigen'));
    confirm.type = 'submit';
    actions.append(cancel, confirm);
    form.append(header);
    if (isPrompt) form.append(body);
    form.append(actions);
    dialog.append(form);

    form.addEventListener('submit', event => {
      event.preventDefault();
      if (field) {
        if (field.required && !field.value.trim()) {
          field.setCustomValidity('Bitte geben Sie einen Wert ein.');
          field.reportValidity();
          return;
        }
        if (!field.reportValidity()) return;
      }
      finish(isPrompt ? field.value : true);
    });
    dialog.addEventListener('cancel', event => {
      event.preventDefault();
      finish(cancelledValue);
    });
    dialog.addEventListener('close', () => finish(cancelledValue));
    document.body.append(dialog);
    try {
      dialog.showModal();
      if (field) {
        field.focus({ preventScroll: true });
        field.select();
      } else {
        // Keep destructive actions behind an explicit choice.
        cancel.focus({ preventScroll: true });
      }
    } catch {
      // A detached page or unsupported modal must never authorize an action.
      finish(cancelledValue);
    }
  }

  function request(kind, options) {
    return new Promise(resolve => {
      const focused = document.activeElement;
      queue.push({ kind, options: options || {}, resolve,
        focusTarget: active && active.focusTarget || focused });
      advance();
    });
  }

  window.UI = Object.assign(window.UI || {}, {
    confirm: options => request('confirm', options),
    prompt: options => request('prompt', options)
  });
})();
