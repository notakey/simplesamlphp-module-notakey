/**
 * Notakey authentication page helpers: submit button state and
 * polling of the authentication request status.
 */
(function () {
    'use strict';

    var REQUEST_TIMEOUT = 10000;

    function request(url, onSuccess, onError) {
        var controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
        var timer = controller ? setTimeout(function () { controller.abort(); }, REQUEST_TIMEOUT) : null;

        fetch(url, {
            cache: 'no-store',
            credentials: 'same-origin',
            signal: controller ? controller.signal : undefined
        }).then(function (response) {
            if (!response.ok) {
                throw new Error('HTTP ' + response.status);
            }
            return response.text();
        }).then(function (data) {
            if (timer) { clearTimeout(timer); }
            onSuccess(data.trim());
        }).catch(function (err) {
            if (timer) { clearTimeout(timer); }
            if (window.console) { console.log('Notakey status request failed: ' + err); }
            onError();
        });
    }

    function isFinal(status) {
        return status === 'approved' || status === 'denied' || status === 'expired';
    }

    function poll(url, authUrl, interval, errorInterval, redirectOnError) {
        request(url, function (status) {
            if (isFinal(status)) {
                window.location.href = authUrl;
            } else {
                setTimeout(function () { poll(url, authUrl, interval, errorInterval, redirectOnError); }, interval);
            }
        }, function () {
            if (redirectOnError) {
                window.location.href = authUrl;
            } else {
                setTimeout(function () { poll(url, authUrl, interval, errorInterval, redirectOnError); }, errorInterval);
            }
        });
    }

    function init() {
        var buttons = document.querySelectorAll('.ntk-submit');
        Array.prototype.forEach.call(buttons, function (button) {
            if (!button.form) { return; }
            button.form.addEventListener('submit', function () {
                if (button.dataset.processing) {
                    button.value = button.dataset.processing;
                }
                setTimeout(function () { button.disabled = true; }, 0);
            });
        });

        var root = document.getElementById('authContent');
        if (!root) { return; }

        var authUrl = root.dataset.authUrl;

        if (root.dataset.statusUrl) {
            setTimeout(function () { poll(root.dataset.statusUrl, authUrl, 2010, 2010, true); }, 500);
        }

        if (root.dataset.qrstatUrl) {
            setTimeout(function () { poll(root.dataset.qrstatUrl, authUrl, 3010, 3020, false); }, 1000);
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
}());
